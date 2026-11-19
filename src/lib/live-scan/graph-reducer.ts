/**
 * Real Time Scanning — the one reducer from event log to graph.
 *
 * Used by the backend (snapshots, persisted summary) and the browser (live
 * canvas, timeline replay). Properties the live view depends on:
 *
 * • Idempotent — an event already applied (same seq) is ignored, so replay
 *   after reconnect, a duplicated frame, or snapshot+stream overlap cannot
 *   double a node, an edge or a count.
 * • Order-tolerant — an entity update older than the entity's last applied
 *   sequence is dropped, so a late frame cannot roll a node back.
 * • Never resets — applying events only adds or updates; nothing is cleared.
 */

import type {
  LiveEdge, LiveEvent, LiveEvidence, LiveFinding, LiveNode, NodeKind, RunMeta, Severity,
} from './types'
import { TERMINAL_STATUSES } from './types'

export interface LiveGraphState {
  meta: RunMeta | null
  nodes: Record<string, LiveNode>
  edges: Record<string, LiveEdge>
  findings: Record<string, LiveFinding>
  evidence: Record<string, LiveEvidence>
  /** Highest sequence applied. */
  lastSeq: number
  /** Count of distinct events applied (equals lastSeq when nothing was lost). */
  applied: number
  appliedSeqs: Set<number>
}

export function emptyGraph(): LiveGraphState {
  return { meta: null, nodes: {}, edges: {}, findings: {}, evidence: {}, lastSeq: 0, applied: 0, appliedSeqs: new Set() }
}

export function hasMeasuredSurface(graph: LiveGraphState): boolean {
  return Object.values(graph.nodes).some((node) => node.kind === 'certificate' || node.kind === 'application' ||
    (node.kind === 'endpoint' && node.data.handshake === 'completed'))
}

/** Legacy observations can overstate vendor attribution or name an unverified anchor. */
export function relationshipVerification(edge: LiveEdge): LiveEdge['verification'] {
  if (edge.type === 'BACKED_BY' || edge.type === 'MANAGED_BY_VENDOR' || edge.type === 'TRUSTED_BY_STORE' ||
    (edge.type === 'CHAIN_VALIDATED_TO' && !edge.target.startsWith('truststore:'))) return 'inferred'
  return edge.verification
}

export function findingsForNode(graph: LiveGraphState, node: LiveNode): LiveFinding[] {
  return Object.values(graph.findings).filter((finding) =>
    finding.affectedNodeIds.includes(node.id) ||
    (node.kind === 'asset' && finding.affectedTargets.some((target) => node.targets.includes(target))),
  )
}

/** Keep evidence and relationships with their discovery, yielding before the next card. */
export function liveFrameLength(graph: LiveGraphState, events: readonly LiveEvent[]): number {
  let firstCard: string | undefined
  for (const [index, { payload }] of events.entries()) {
    const id = payload.node?.id
    if (!id || Object.hasOwn(graph.nodes, id)) continue
    if (firstCard && id !== firstCard) return index
    firstCard = id
  }
  return events.length
}

function mergeUnique(a: string[], b: string[]): string[] {
  if (!b.length) return a
  const out = a.slice()
  for (const item of b) if (!out.includes(item)) out.push(item)
  return out
}

function upsertNode(nodes: Record<string, LiveNode>, incoming: LiveNode, seq: number): void {
  const existing = nodes[incoming.id]
  if (!existing) {
    nodes[incoming.id] = { ...incoming, firstSeq: incoming.firstSeq || seq, lastSeq: seq }
    return
  }
  if (seq < existing.lastSeq) return
  nodes[incoming.id] = {
    ...existing,
    ...incoming,
    firstSeq: existing.firstSeq,
    lastSeq: seq,
    targets: mergeUnique(existing.targets, incoming.targets),
    evidenceIds: mergeUnique(existing.evidenceIds, incoming.evidenceIds),
    data: { ...existing.data, ...incoming.data },
  }
}

function upsertEdge(edges: Record<string, LiveEdge>, incoming: LiveEdge, seq: number): void {
  const existing = edges[incoming.id]
  if (!existing) {
    edges[incoming.id] = { ...incoming, firstSeq: incoming.firstSeq || seq, lastSeq: seq }
    return
  }
  if (seq < existing.lastSeq) return
  edges[incoming.id] = { ...existing, ...incoming, firstSeq: existing.firstSeq, lastSeq: seq }
}

function upsertFinding(findings: Record<string, LiveFinding>, incoming: LiveFinding): void {
  const existing = findings[incoming.id]
  if (!existing) {
    findings[incoming.id] = incoming
    return
  }
  findings[incoming.id] = {
    ...existing,
    ...incoming,
    firstSeen: existing.firstSeen < incoming.firstSeen ? existing.firstSeen : incoming.firstSeen,
    affectedNodeIds: mergeUnique(existing.affectedNodeIds, incoming.affectedNodeIds),
    affectedTargets: mergeUnique(existing.affectedTargets, incoming.affectedTargets),
    evidenceIds: mergeUnique(existing.evidenceIds, incoming.evidenceIds),
    observed: { ...existing.observed, ...incoming.observed },
  }
}

/**
 * Apply a batch of events. Returns a NEW state object (maps are copied once
 * per batch, not per event) so React sees a change, or the SAME object when
 * nothing in the batch was new.
 */
export function applyEvents(state: LiveGraphState, events: LiveEvent[]): LiveGraphState {
  const fresh = events.filter((event) => !state.appliedSeqs.has(event.seq))
  if (!fresh.length) return state
  fresh.sort((a, b) => a.seq - b.seq)

  const next: LiveGraphState = {
    meta: state.meta,
    nodes: { ...state.nodes },
    edges: { ...state.edges },
    findings: { ...state.findings },
    evidence: { ...state.evidence },
    lastSeq: state.lastSeq,
    applied: state.applied,
    appliedSeqs: new Set(state.appliedSeqs),
  }

  for (const event of fresh) {
    next.appliedSeqs.add(event.seq)
    next.applied += 1
    if (event.seq > next.lastSeq) next.lastSeq = event.seq
    const { payload } = event
    if (payload.run) {
      // A terminal status is final: a late progress frame cannot reopen a run.
      const terminal = next.meta && TERMINAL_STATUSES.includes(next.meta.status)
      const merged = { ...(next.meta ?? {}), ...payload.run } as RunMeta
      if (terminal && payload.run.status && !TERMINAL_STATUSES.includes(payload.run.status) && event.type !== 'scan.started') {
        merged.status = next.meta!.status
      }
      next.meta = merged
    }
    if (payload.evidence) next.evidence[payload.evidence.id] = payload.evidence
    if (payload.node) upsertNode(next.nodes, payload.node, event.seq)
    if (payload.edge) upsertEdge(next.edges, payload.edge, event.seq)
    if (payload.edgeId && event.type === 'relationship.removed') delete next.edges[payload.edgeId]
    if (payload.finding) upsertFinding(next.findings, payload.finding)
  }
  return next
}

/** Rebuild from a log prefix — the timeline view and the server snapshot. */
export function buildGraph(events: LiveEvent[], uptoSeq = Number.POSITIVE_INFINITY): LiveGraphState {
  return applyEvents(emptyGraph(), events.filter((event) => event.seq <= uptoSeq))
}

/* ------------------------------------------------------------------ */
/* Summary — the single source for header, summary panel and export    */
/* ------------------------------------------------------------------ */

export interface LiveSummary {
  assetsDiscovered: number
  endpointsInspected: number
  endpointsFailed: number
  certificatesAnalyzed: number
  chainsValidated: number
  chainsFailed: number
  chainsUnknown: number
  algorithmsObserved: number
  quantumExposedAssets: number
  findingsBySeverity: Record<Severity, number>
  findingsTotal: number
  unknownAssessments: number
  relationshipsVerified: number
  relationshipsInferred: number
  progressPercent: number | null
  targetsTotal: number
  targetsDone: number
}

const byKind = (state: LiveGraphState, kind: NodeKind) => Object.values(state.nodes).filter((node) => node.kind === kind)

export function summarize(state: LiveGraphState): LiveSummary {
  const endpoints = byKind(state, 'endpoint')
  const findings = Object.values(state.findings).filter((finding) => finding.status === 'open' || finding.status === 'unknown')
  const findingsBySeverity: Record<Severity, number> = { critical: 0, high: 0, medium: 0, low: 0, info: 0 }
  for (const finding of findings) findingsBySeverity[finding.severity] += 1

  // An asset is quantum-exposed when an open quantum-migration finding affects
  // one of its targets. Failed or unmeasured assets are NOT counted as safe —
  // they land in `unknownAssessments` instead.
  const exposedTargets = new Set<string>()
  for (const finding of findings) {
    if (finding.exposure !== 'quantum-migration' || finding.severity === 'info') continue
    for (const target of finding.affectedTargets) exposedTargets.add(target)
  }
  const assets = byKind(state, 'asset')
  const unknownAssets = assets.filter((asset) => asset.status === 'failed' || asset.status === 'unknown').length
  const chainsUnknown = endpoints.filter((endpoint) => endpoint.data.handshake === 'completed' && endpoint.data.chainTrusted == null).length

  const meta = state.meta
  const targetsTotal = meta?.targets.length ?? 0
  const targetsDone = (meta?.completedTargets.length ?? 0) + (meta?.failedTargets.length ?? 0)
  const edges = Object.values(state.edges)

  return {
    assetsDiscovered: assets.length,
    endpointsInspected: endpoints.filter((endpoint) => endpoint.data.handshake === 'completed').length,
    endpointsFailed: endpoints.filter((endpoint) => endpoint.data.handshake === 'failed').length,
    certificatesAnalyzed: byKind(state, 'certificate').length,
    chainsValidated: endpoints.filter((endpoint) => endpoint.data.chainTrusted === true).length,
    chainsFailed: endpoints.filter((endpoint) => endpoint.data.chainTrusted === false).length,
    chainsUnknown,
    algorithmsObserved: byKind(state, 'algorithm').length,
    quantumExposedAssets: assets.filter((asset) => asset.targets.some((target) => exposedTargets.has(target))).length,
    findingsBySeverity,
    findingsTotal: findings.length,
    unknownAssessments: unknownAssets + chainsUnknown,
    relationshipsVerified: edges.filter((edge) => ['validated', 'observed'].includes(relationshipVerification(edge))).length,
    relationshipsInferred: edges.filter((edge) => relationshipVerification(edge) === 'inferred').length,
    progressPercent: targetsTotal ? Math.round((targetsDone / targetsTotal) * 100) : null,
    targetsTotal,
    targetsDone,
  }
}

/* ------------------------------------------------------------------ */
/* Neighbourhood — focus, dependency tracing, finding highlight        */
/* ------------------------------------------------------------------ */

export function neighbours(state: LiveGraphState, nodeId: string): Set<string> {
  const out = new Set<string>([nodeId])
  for (const edge of Object.values(state.edges)) {
    if (edge.source === nodeId) out.add(edge.target)
    if (edge.target === nodeId) out.add(edge.source)
  }
  return out
}

/** Transitive trace in one direction along stored edge direction. */
export function trace(state: LiveGraphState, nodeId: string, direction: 'upstream' | 'downstream' | 'both', maxDepth = 6): Set<string> {
  const seen = new Set<string>([nodeId])
  let frontier = [nodeId]
  const edges = Object.values(state.edges)
  for (let depth = 0; depth < maxDepth && frontier.length; depth++) {
    const next: string[] = []
    for (const id of frontier) {
      for (const edge of edges) {
        if ((direction === 'downstream' || direction === 'both') && edge.source === id && !seen.has(edge.target)) {
          seen.add(edge.target); next.push(edge.target)
        }
        if ((direction === 'upstream' || direction === 'both') && edge.target === id && !seen.has(edge.source)) {
          seen.add(edge.source); next.push(edge.source)
        }
      }
    }
    frontier = next
  }
  return seen
}

/* ------------------------------------------------------------------ */
/* Finding groups — presentation-only collapse of large finding sets   */
/* ------------------------------------------------------------------ */

export const GROUP_PREFIX = 'group:'

const NODE_STATUS_RANK: Record<LiveNode['status'], number> = {
  validated: 0, observed: 1, active: 1, unknown: 2, exposure: 3, failed: 4, critical: 5,
}
const SEVERITY_ORDER: Severity[] = ['info', 'low', 'medium', 'high', 'critical']

/**
 * Collapse findings of the same type on the same primary entity into one
 * group node when there are at least `minSize` of them. Records are untouched:
 * this returns a DISPLAY copy whose group nodes list their members, and the
 * edges into members are re-pointed at the group. `expanded` group ids render
 * their members individually.
 */
export function clusterFindings(state: LiveGraphState, expanded: Set<string>, minSize = 2): LiveGraphState {
  const buckets = new Map<string, LiveFinding[]>()
  for (const finding of Object.values(state.findings)) {
    if (!state.nodes[finding.id]) continue
    // One group per finding KIND across the estate (type + the title's category
    // prefix, so the generic posture type splits by what the rule measured).
    const key = `${GROUP_PREFIX}${finding.type}|${finding.title.split(':')[0].trim().toLowerCase()}`
    const list = buckets.get(key) ?? []
    list.push(finding)
    buckets.set(key, list)
  }
  const memberToGroup = new Map<string, string>()
  const nodes: Record<string, LiveNode> = { ...state.nodes }
  for (const [groupId, members] of buckets) {
    if (members.length < minSize || expanded.has(groupId)) continue
    const memberNodes = members.map((finding) => state.nodes[finding.id])
    const worstSeverity = members.reduce<Severity>((worst, finding) => (SEVERITY_ORDER.indexOf(finding.severity) > SEVERITY_ORDER.indexOf(worst) ? finding.severity : worst), 'info')
    const worstStatus = memberNodes.reduce((worst, node) => (NODE_STATUS_RANK[node.status] > NODE_STATUS_RANK[worst] ? node.status : worst), memberNodes[0].status)
    const affected = new Set(members.flatMap((finding) => finding.affectedNodeIds))
    for (const finding of members) { memberToGroup.set(finding.id, groupId); delete nodes[finding.id] }
    nodes[groupId] = {
      id: groupId,
      kind: 'finding',
      label: `${members.length} ${members[0].title.split(':')[0]} findings`,
      sublabel: `${affected.size} affected entit${affected.size === 1 ? 'y' : 'ies'} · click to expand`,
      status: worstStatus,
      targets: [...new Set(members.flatMap((finding) => finding.affectedTargets))],
      observedAt: memberNodes[memberNodes.length - 1].observedAt,
      firstSeq: Math.min(...memberNodes.map((node) => node.firstSeq)),
      lastSeq: Math.max(...memberNodes.map((node) => node.lastSeq)),
      evidenceIds: [],
      data: {
        cluster: true,
        memberIds: members.map((finding) => finding.id),
        severity: worstSeverity,
        exposure: members[0].exposure,
        type: members[0].type,
        titles: members.map((finding) => finding.title),
      },
    }
  }
  if (!memberToGroup.size) return state
  const edges: Record<string, LiveEdge> = {}
  for (const edge of Object.values(state.edges)) {
    const source = memberToGroup.get(edge.source) ?? edge.source
    const target = memberToGroup.get(edge.target) ?? edge.target
    if (source === edge.source && target === edge.target) { edges[edge.id] = edge; continue }
    const id = `${edge.type}:${source}->${target}`
    const existing = edges[id]
    const risk = existing && (existing.risk === 'critical' || (existing.risk === 'exposure' && edge.risk === 'none')) ? existing.risk : edge.risk
    edges[id] = { ...(existing ?? edge), id, source, target, risk, firstSeq: Math.min(existing?.firstSeq ?? edge.firstSeq, edge.firstSeq) }
  }
  return { ...state, nodes, edges }
}
