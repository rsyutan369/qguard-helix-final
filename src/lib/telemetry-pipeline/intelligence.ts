/**
 * Telemetry pipeline engine.
 *
 * Pure and isomorphic. Computes collector health, ingestion lag, source
 * freshness, signal quality and coverage from the tenant's own rows.
 *
 * ── Counting rule ──────────────────────────────────────────────────────────
 * Every count is of ROWS IN A NAMED TABLE, and every percentage publishes its
 * denominator. The page this replaces built one flattened array from ~25 tables
 * and reported its length under a dozen different labels — 593 "keys" for a
 * tenant with none, 279 "cloud assets" with no connector configured.
 *
 * ── Absence rule ───────────────────────────────────────────────────────────
 * A source with no rows is `absent`, not `healthy`. A collector that has never
 * sent a heartbeat is `silent`, not `online`. Nothing here reads an empty
 * result as a good one — on a telemetry console that would be the single most
 * misleading thing it could do.
 */

import type {
  CollectorFleet,
  CollectorRecord,
  CoverageRecord,
  HealthState,
  IngestionLag,
  PipelineFinding,
  PipelinePosture,
  QualityIssue,
  Severity,
  SignalQuality,
  SourceHealth,
  SourceKey,
  TelemetryCoverage,
  TelemetryPipelineIntelligence,
  ThroughputPoint,
} from './types'
import type { SourceRead } from '@/lib/source-read'
import { isRuntimeOperationObservation } from '@/lib/telemetry/evidence-identity'

type Row = Record<string, unknown>

const MINUTE = 60_000
const HOUR = 60 * MINUTE
const DAY = 24 * HOUR

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

function clamp(value: number, min = 0, max = 100): number {
  if (!Number.isFinite(value)) return min
  return Math.max(min, Math.min(max, Math.round(value)))
}

function recordOf(value: unknown): Record<string, unknown> {
  if (typeof value === 'string' && value.trim()) {
    try {
      const parsed = JSON.parse(value)
      return parsed && typeof parsed === 'object' && !Array.isArray(parsed) ? (parsed as Record<string, unknown>) : {}
    } catch {
      return {}
    }
  }
  return value && typeof value === 'object' && !Array.isArray(value) ? (value as Record<string, unknown>) : {}
}

function dateMs(value: unknown): number {
  const ms = Date.parse(str(value))
  return Number.isFinite(ms) ? ms : 0
}

function isoOrNull(value: unknown): string | null {
  const ms = dateMs(value)
  return ms ? new Date(ms).toISOString() : null
}

function latestMs(rows: Row[], ...columns: string[]): number {
  let best = 0
  for (const row of rows) {
    for (const column of columns) {
      const ms = dateMs(row[column])
      if (ms > best) best = ms
    }
  }
  return best
}

function percentOf(value: number, total: number): number {
  return total > 0 ? clamp((value / total) * 100) : 0
}

function percentile(sorted: number[], fraction: number): number {
  if (!sorted.length) return 0
  const index = Math.min(sorted.length - 1, Math.max(0, Math.ceil(fraction * sorted.length) - 1))
  return sorted[index]
}

function pick(record: Record<string, unknown>, keys: string[]): string {
  for (const key of keys) {
    const value = str(record[key])
    if (value) return value
  }
  return ''
}

function uniq<T>(values: T[]): T[] {
  return [...new Set(values)]
}

/* ------------------------------------------------------------------ */
/* Source registry                                                     */
/* ------------------------------------------------------------------ */

/**
 * What each source feeds, and how stale it may get before it stops being
 * trustworthy.
 *
 * `feeds` is what makes a staleness verdict actionable: a stale source is only
 * interesting because of what it degrades downstream.
 */
const SOURCE_REGISTRY: Array<{
  key: SourceKey
  label: string
  feeds: string[]
  thresholdMs: number
  /** Column carrying the event's own time, best first. */
  timeColumns: string[]
}> = [
  {
    key: 'runtime_crypto_events',
    label: 'Runtime crypto events',
    feeds: ['Runtime Crypto Intelligence', 'TLS Telemetry', 'Encryption Monitoring', 'Drift Detection'],
    thresholdMs: 6 * HOUR,
    timeColumns: ['observed_at', 'created_at'],
  },
  {
    key: 'scanner_evidence',
    label: 'Agent evidence',
    feeds: ['TLS Telemetry', 'Encryption Monitoring', 'Agent Collector Console'],
    thresholdMs: 24 * HOUR,
    timeColumns: ['observed_at', 'processed_at', 'created_at'],
  },
  {
    key: 'scanner_alerts',
    label: 'Collector alerts',
    feeds: ['Scanner', 'Quantum Risk Analysis', 'TLS Orchestrator'],
    thresholdMs: 24 * HOUR,
    timeColumns: ['updated_at', 'created_at'],
  },
  {
    key: 'crypto_inventory',
    label: 'Crypto inventory (CBOM)',
    feeds: ['CBOM Explorer', 'Assets', 'Quantum Readiness', 'Encryption Monitoring'],
    thresholdMs: 7 * DAY,
    timeColumns: ['discovered_at', 'created_at'],
  },
  {
    key: 'pqc_scan_results',
    label: 'Scan findings',
    feeds: ['Scanner', 'Quantum Readiness', 'Migration Planner'],
    thresholdMs: 7 * DAY,
    timeColumns: ['created_at'],
  },
  {
    key: 'crypto_exposures',
    label: 'Crypto exposures',
    feeds: ['Quantum Readiness', 'Harvest Now', 'Quantum Risk Analysis'],
    thresholdMs: 7 * DAY,
    timeColumns: ['updated_at', 'created_at'],
  },
  {
    key: 'certificates',
    label: 'Certificate store',
    feeds: ['PKI Visibility', 'TLS Telemetry', 'Quantum Certification'],
    thresholdMs: 7 * DAY,
    timeColumns: ['updated_at', 'created_at'],
  },
  {
    key: 'generated_keys',
    label: 'Key material',
    feeds: ['QKMS', 'Encryption Monitoring'],
    thresholdMs: 30 * DAY,
    timeColumns: ['updated_at', 'created_at'],
  },
  {
    key: 'security_events',
    label: 'Security events',
    feeds: ['Security Events', 'TLS Orchestrator drift', 'Audit Vault'],
    thresholdMs: 7 * DAY,
    timeColumns: ['created_at'],
  },
  {
    key: 'agent_heartbeats',
    label: 'Collector heartbeats',
    feeds: ['Agent Collector Console', 'Collector fleet health'],
    thresholdMs: 15 * MINUTE,
    timeColumns: ['observed_at', 'created_at'],
  },
  {
    key: 'migration_jobs',
    label: 'Migration jobs',
    feeds: ['Live Migration Ops', 'TLS Orchestrator', 'Migration Planner'],
    thresholdMs: 30 * DAY,
    timeColumns: ['updated_at', 'created_at'],
  },
  {
    key: 'vault_files',
    label: 'Quantum Vault',
    feeds: ['Vault', 'Encryption Monitoring'],
    thresholdMs: 30 * DAY,
    timeColumns: ['updated_at', 'created_at'],
  },
]

/* ------------------------------------------------------------------ */
/* Inputs                                                              */
/* ------------------------------------------------------------------ */

export interface PipelineInputs {
  assets: Array<{ id: string; name: string; environment: string }>
  rowsBySource: Record<SourceKey, Row[]>
  /** Sources whose fetch hit the row cap, so their count is a lower bound. */
  truncatedSources?: SourceKey[]
  scannerAgents: Row[]
  connectorAccounts: Row[]
  reads?: SourceRead[]
  now?: number
}

/* ================================================================== */
/* Engine                                                              */
/* ================================================================== */

export function buildTelemetryPipelineIntelligence(inputs: PipelineInputs): TelemetryPipelineIntelligence {
  const now = inputs.now ?? Date.now()
  const rows = inputs.rowsBySource
  const runtimeEvents = rows.runtime_crypto_events ?? []
  const heartbeats = rows.agent_heartbeats ?? []

  /* ---------------------------------------------------------------- */
  /* 1. Source health                                                  */
  /* ---------------------------------------------------------------- */

  const sources: SourceHealth[] = SOURCE_REGISTRY.map((entry) => {
    const data = rows[entry.key] ?? []
    const lastMs = latestMs(data, ...entry.timeColumns)
    const ageMs = lastMs ? now - lastMs : null
    const truncated = inputs.truncatedSources?.includes(entry.key) || inputs.reads?.some((read) => read.key === entry.key && read.state === 'truncated') || false

    let health: HealthState
    let detail: string
    if (inputs.reads?.some((read) => read.key === entry.key && read.state === 'unavailable')) {
      health = 'unavailable'
      detail = 'Source query failed. Its counts and freshness are unavailable.'
    } else if (data.length === 0) {
      health = 'absent'
      detail = `No rows. ${entry.feeds.join(', ')} ${entry.feeds.length === 1 ? 'has' : 'have'} no input from this source — any zero they show is unmeasured, not clean.`
    } else if (ageMs === null) {
      health = 'degraded'
      detail = 'Rows exist but none carry a usable timestamp, so freshness cannot be judged.'
    } else if (ageMs <= entry.thresholdMs) {
      health = 'healthy'
      detail = `Newest row is inside the ${formatDuration(entry.thresholdMs)} freshness window for this source.`
    } else if (ageMs <= entry.thresholdMs * 4) {
      health = 'stale'
      detail = `Newest row is ${formatDuration(ageMs)} old against a ${formatDuration(entry.thresholdMs)} window. Downstream figures are still shown but are no longer current.`
    } else {
      health = 'silent'
      detail = `Nothing for ${formatDuration(ageMs)}. Treat everything derived from this source as historical.`
    }

    return {
      key: entry.key,
      label: entry.label,
      feeds: entry.feeds,
      rows: data.length,
      health,
      lastEventAt: lastMs ? new Date(lastMs).toISOString() : null,
      ageMs,
      thresholdMs: entry.thresholdMs,
      detail,
      truncated,
    }
  })

  /* ---------------------------------------------------------------- */
  /* 2. Collector fleet                                                */
  /* ---------------------------------------------------------------- */

  const fleet = buildFleet({ agents: inputs.scannerAgents, heartbeats, runtimeEvents, now })

  /* ---------------------------------------------------------------- */
  /* 3. Ingestion lag                                                  */
  /* ---------------------------------------------------------------- */

  const ingestion = buildIngestionLag(rows)

  /* ---------------------------------------------------------------- */
  /* 4. Throughput                                                     */
  /* ---------------------------------------------------------------- */

  const throughput = buildThroughput(rows, now)

  /* ---------------------------------------------------------------- */
  /* 5. Signal quality                                                 */
  /* ---------------------------------------------------------------- */

  const quality = buildSignalQuality({ runtimeEvents, evidence: rows.scanner_evidence ?? [] })

  /* ---------------------------------------------------------------- */
  /* 6. Coverage                                                       */
  /* ---------------------------------------------------------------- */

  const coverage = buildCoverage({ assets: inputs.assets, rows, now })

  /* ---------------------------------------------------------------- */
  /* 7. Posture                                                        */
  /* ---------------------------------------------------------------- */

  const eventsLast24h = countSince(rows, now - DAY)
  const eventsLast7d = countSince(rows, now - 7 * DAY)
  const withRows = sources.filter((source) => source.rows > 0)
  const stalest = withRows
    .filter((source) => source.ageMs !== null)
    .sort((a, b) => (b.ageMs ?? 0) - (a.ageMs ?? 0))[0]
  const freshest = withRows
    .filter((source) => source.ageMs !== null)
    .sort((a, b) => (a.ageMs ?? 0) - (b.ageMs ?? 0))[0]

  /*
   * Four equally-weighted dimensions. Collection is weighted alongside the
   * others rather than dominating, because a tenant can have healthy sources
   * fed by scans with no live collector at all — that is a real and supported
   * configuration, not a failure.
   */
  const activeConnectors = inputs.connectorAccounts.filter((account) => ['active', 'connected', 'ok'].includes(str(account.status).toLowerCase()))
  const freshConnectors = activeConnectors.filter((account) => {
    const synced = dateMs(account.last_sync_at)
    return synced > 0 && synced <= now && now - synced <= DAY
  })
  const collectionScore = fleet.measured
    ? percentOf(fleet.healthy, Math.max(1, fleet.total))
    : percentOf(freshConnectors.length, inputs.connectorAccounts.length)
  const freshnessScore = percentOf(sources.filter((source) => source.health === 'healthy').length, Math.max(1, sources.length))
  const attributionScore = 100 - coverage.unattributedPercent
  const pipelineHealthScore = clamp((collectionScore + freshnessScore + attributionScore + quality.score) / 4)

  const healthState: HealthState =
    pipelineHealthScore >= 80 ? 'healthy' : pipelineHealthScore >= 55 ? 'degraded' : pipelineHealthScore >= 25 ? 'stale' : 'silent'

  const posture: PipelinePosture = {
    pipelineHealthScore,
    healthState,
    headline: headlineFor({ healthState, fleet, sources, coverage, quality }),
    collectorsOnline: fleet.healthy,
    collectorsTotal: fleet.total,
    connectorsActive: activeConnectors.length,
    connectorsTotal: inputs.connectorAccounts.length,
    eventsLast24h,
    eventsLast7d,
    ingestionP50Ms: ingestion.p50Ms,
    ingestionP95Ms: ingestion.p95Ms,
    sourcesHealthy: sources.filter((source) => source.health === 'healthy').length,
    sourcesTotal: sources.length,
    sourcesAbsent: sources.filter((source) => source.health === 'absent').length,
    coveragePercent: coverage.coveragePercent,
    qualityScore: quality.score,
    freshestSource: freshest?.label ?? null,
    stalestSource: stalest?.label ?? null,
    stalestAgeMs: stalest?.ageMs ?? null,
  }

  /* ---------------------------------------------------------------- */
  /* 8. Findings                                                       */
  /* ---------------------------------------------------------------- */

  const findings = buildFindings({ fleet, sources, quality, coverage, ingestion, now })

  const sourceCounts: Record<string, number> = {}
  for (const source of sources) sourceCounts[source.key] = source.rows
  sourceCounts.scanner_agents = inputs.scannerAgents.length
  sourceCounts.connector_accounts = inputs.connectorAccounts.length
  sourceCounts.assets = inputs.assets.length

  return {
    generatedAt: new Date(now).toISOString(),
    latestEvidenceAt: freshest?.lastEventAt ?? null,
    hasData: withRows.length > 0 || fleet.total > 0,
    posture,
    fleet,
    ingestion,
    throughput,
    sources,
    quality,
    coverage,
    findings,
    sourceCounts,
    reads: inputs.reads ?? [],
    truncated: Boolean(inputs.truncatedSources?.length || inputs.reads?.some((read) => read.state === 'truncated')),
  }
}

/* ================================================================== */
/* Collector fleet                                                     */
/* ================================================================== */

function buildFleet(input: { agents: Row[]; heartbeats: Row[]; runtimeEvents: Row[]; now: number }): CollectorFleet {
  const { agents, heartbeats, runtimeEvents, now } = input

  const heartbeatsByAgent = new Map<string, Row[]>()
  for (const beat of heartbeats) {
    const id = str(beat.agent_id)
    if (!id) continue
    const bucket = heartbeatsByAgent.get(id)
    if (bucket) bucket.push(beat)
    else heartbeatsByAgent.set(id, [beat])
  }

  const eventsByAgent = new Map<string, number>()
  for (const event of runtimeEvents) {
    const id = str(event.agent_id)
    if (!id) continue
    eventsByAgent.set(id, (eventsByAgent.get(id) || 0) + 1)
  }

  const collectors: CollectorRecord[] = agents.map((agent) => {
    const id = str(agent.id)
    const metadata = recordOf(agent.metadata)
    const beats = heartbeatsByAgent.get(id) ?? []
    const lastHeartbeatMs = latestMs(beats, 'observed_at', 'created_at')
    const lastSeenMs = Math.max(dateMs(agent.last_seen_at), lastHeartbeatMs)
    const silentForMs = lastSeenMs ? now - lastSeenMs : null
    const eventsAttributed = eventsByAgent.get(id) ?? 0
    const reportedStatus = str(agent.status) || 'unknown'

    /*
     * Health is derived from EVIDENCE, and may contradict `status`. A row can
     * say "online" while nothing has arrived for days; on this tenant the one
     * registered collector says "offline" with a null `last_seen_at` and zero
     * heartbeats, yet events are arriving from a `local-agent` source. Showing
     * the stored status alone would hide both cases.
     */
    let health: HealthState
    let healthReason: string
    if (agent.revoked_at || reportedStatus.toLowerCase() === 'revoked') {
      health = 'unavailable'
      healthReason = 'Collector enrollment was revoked.'
    } else if (!lastSeenMs && beats.length === 0 && eventsAttributed === 0) {
      health = 'silent'
      healthReason = 'Registered but has never sent a heartbeat or an attributable event.'
    } else if (silentForMs !== null && silentForMs > 24 * HOUR) {
      health = 'silent'
      healthReason = `Nothing received for ${formatDuration(silentForMs)}.`
    } else if (silentForMs !== null && silentForMs > 10 * MINUTE) {
      health = 'stale'
      healthReason = `Last contact ${formatDuration(silentForMs)} ago, beyond the 10-minute online window.`
    } else if (beats.length === 0 && eventsAttributed > 0) {
      health = 'degraded'
      healthReason = 'Producing events but no heartbeats, so availability cannot be monitored.'
    } else {
      health = 'healthy'
      healthReason = 'Heartbeats arriving inside the expected interval.'
    }

    return {
      id,
      name: str(agent.name) || 'Collector',
      hostname: str(agent.hostname) || 'Not recorded',
      platform: str(agent.platform) || 'Not recorded',
      reportedStatus,
      health,
      healthReason,
      lastSeenAt: lastSeenMs ? new Date(lastSeenMs).toISOString() : null,
      silentForMs,
      heartbeatsReceived: beats.length,
      lastHeartbeatAt: lastHeartbeatMs ? new Date(lastHeartbeatMs).toISOString() : null,
      eventsAttributed,
      enrolledAt: isoOrNull(agent.created_at),
      environment: pick(metadata, ['environment']) || 'Not recorded',
      version: pick(metadata, ['version', 'agentVersion']) || 'Not recorded',
    }
  })

  /*
   * Events whose source names a collector class but which carry no `agent_id`.
   * They are real evidence that cannot be traced to a registered collector —
   * an integrity gap the fleet table alone would never reveal.
   */
  const collectorSourced = runtimeEvents.filter((event) => /agent|collector/i.test(str(event.source_type)))
  const unattributableEvents = collectorSourced.filter((event) => !str(event.agent_id)).length
  const registeredIds = new Set(collectors.map((collector) => collector.id))
  const unregisteredSources = uniq(
    runtimeEvents
      .filter((event) => {
        const agentId = str(event.agent_id)
        return agentId ? !registeredIds.has(agentId) : /agent|collector/i.test(str(event.source_type))
      })
      .map((event) => str(event.source_type))
      .filter(Boolean),
  )

  return {
    measured: agents.length > 0,
    collectors: collectors.sort((a, b) => (a.health === 'healthy' ? 1 : 0) - (b.health === 'healthy' ? 1 : 0)),
    total: collectors.length,
    healthy: collectors.filter((collector) => collector.health === 'healthy').length,
    degraded: collectors.filter((collector) => collector.health === 'degraded' || collector.health === 'stale').length,
    silent: collectors.filter((collector) => collector.health === 'silent').length,
    heartbeatsTotal: heartbeats.length,
    unattributableEvents,
    unregisteredSources,
  }
}

/* ================================================================== */
/* Ingestion lag                                                       */
/* ================================================================== */

/** Sources carrying both an observation time and a persistence time. */
const LAG_SOURCES: Array<{ key: SourceKey; label: string; observed: string; persisted: string }> = [
  { key: 'runtime_crypto_events', label: 'Runtime crypto events', observed: 'observed_at', persisted: 'created_at' },
  { key: 'scanner_evidence', label: 'Agent evidence', observed: 'observed_at', persisted: 'created_at' },
  { key: 'agent_heartbeats', label: 'Collector heartbeats', observed: 'observed_at', persisted: 'created_at' },
]

function buildIngestionLag(rows: Record<SourceKey, Row[]>): IngestionLag {
  const all: number[] = []
  let negative = 0
  const bySource: IngestionLag['bySource'] = []

  for (const entry of LAG_SOURCES) {
    const data = rows[entry.key] ?? []
    const samples: number[] = []
    for (const row of data) {
      const observed = dateMs(row[entry.observed])
      const persisted = dateMs(row[entry.persisted])
      if (!observed || !persisted) continue
      const lag = persisted - observed
      // Negative lag means the persisted time precedes the observed time —
      // clock skew on the collector. Counted, never averaged into the figure.
      if (lag < 0) {
        negative += 1
        continue
      }
      samples.push(lag)
      all.push(lag)
    }
    if (!samples.length) continue
    const sorted = samples.sort((a, b) => a - b)
    bySource.push({
      source: entry.label,
      samples: sorted.length,
      p50Ms: percentile(sorted, 0.5),
      p95Ms: percentile(sorted, 0.95),
      maxMs: sorted[sorted.length - 1],
    })
  }

  const sortedAll = all.sort((a, b) => a - b)
  return {
    measured: sortedAll.length > 0,
    samples: sortedAll.length,
    p50Ms: sortedAll.length ? percentile(sortedAll, 0.5) : null,
    p95Ms: sortedAll.length ? percentile(sortedAll, 0.95) : null,
    maxMs: sortedAll.length ? sortedAll[sortedAll.length - 1] : null,
    negativeSamples: negative,
    bySource: bySource.sort((a, b) => b.samples - a.samples),
  }
}

/* ================================================================== */
/* Throughput                                                          */
/* ================================================================== */

function buildThroughput(rows: Record<SourceKey, Row[]>, now: number): ThroughputPoint[] {
  const start = new Date(now)
  start.setHours(0, 0, 0, 0)
  const tracked = SOURCE_REGISTRY.filter((entry) => (rows[entry.key] ?? []).length > 0).slice(0, 6)

  const points: ThroughputPoint[] = []
  for (let index = 13; index >= 0; index -= 1) {
    const dayStart = start.getTime() - index * DAY
    const dayEnd = dayStart + DAY
    const bySource: Record<string, number> = {}
    let total = 0
    for (const entry of tracked) {
      const count = (rows[entry.key] ?? []).filter((row) => {
        for (const column of entry.timeColumns) {
          const ms = dateMs(row[column])
          if (ms) return ms >= dayStart && ms < dayEnd
        }
        return false
      }).length
      bySource[entry.label] = count
      total += count
    }
    points.push({
      label: new Date(dayStart).toLocaleDateString('en-US', { month: 'short', day: 'numeric' }),
      date: new Date(dayStart).toISOString(),
      bySource,
      total,
    })
  }
  return points
}

function countSince(rows: Record<SourceKey, Row[]>, sinceMs: number): number {
  let total = 0
  for (const entry of SOURCE_REGISTRY) {
    const data = rows[entry.key] ?? []
    total += data.filter((row) => {
      for (const column of entry.timeColumns) {
        const ms = dateMs(row[column])
        if (ms) return ms >= sinceMs
      }
      return false
    }).length
  }
  return total
}

/* ================================================================== */
/* Signal quality                                                      */
/* ================================================================== */

function buildSignalQuality(input: { runtimeEvents: Row[]; evidence: Row[] }): SignalQuality {
  const { runtimeEvents, evidence } = input
  const examined = runtimeEvents.length + evidence.length
  if (!examined) {
    return { measured: false, score: 0, issues: [], rowsExamined: 0 }
  }

  const issues: QualityIssue[] = []
  /**
   * Rows carrying at least one defect, tracked as a SET so the score reflects
   * how many rows are actually affected rather than how many defect types
   * exist. One row commonly exhibits several at once — on this tenant every
   * unattributed runtime event is also unattributable to a collector — and
   * scoring on the worst single rate let one dimension drive the whole figure
   * to zero while well-formed rows from other sources went uncounted.
   */
  const flagged = new Set<string>()
  const issues_flagRows = (rows: Row[], predicate: (row: Row) => boolean, prefix: string) => {
    let count = 0
    rows.forEach((row, index) => {
      if (!predicate(row)) return
      count += 1
      flagged.add(`${prefix}:${str(row.id) || index}`)
    })
    return count
  }
  const add = (issue: Omit<QualityIssue, 'percent'>) => {
    if (issue.count === 0) return
    issues.push({ ...issue, percent: percentOf(issue.count, issue.examined) })
  }

  /* ---- attribution ------------------------------------------------- */
  const noAsset = issues_flagRows(runtimeEvents, (event) => !str(event.asset_id), 'rt')
  add({
    id: 'no-asset-binding',
    label: 'Events with no asset binding',
    count: noAsset,
    examined: runtimeEvents.length,
    severity: noAsset > runtimeEvents.length / 2 ? 'high' : 'medium',
    consequence:
      'These observations cannot be rolled up per asset, so they are excluded from asset coverage and posture on every downstream dashboard.',
    remediation: 'Map the reporting host to an asset, or let the collector enrol it, so its evidence joins the estate view.',
  })

  const collectorSourced = runtimeEvents.filter((event) => /agent|collector/i.test(str(event.source_type)))
  const noAgent = issues_flagRows(collectorSourced, (event) => !str(event.agent_id), 'rt')
  add({
    id: 'no-agent-attribution',
    label: 'Collector events with no collector id',
    count: noAgent,
    examined: collectorSourced.length,
    severity: 'high',
    consequence:
      'Evidence cannot be traced to the collector that produced it, so a misbehaving or compromised collector cannot be isolated from its output.',
    remediation: 'Upgrade the collector so it stamps its agent id on every event, and re-enrol it if the id was never issued.',
  })

  /* ---- duplication ------------------------------------------------- */
  const seen = new Map<string, number>()
  for (const event of runtimeEvents) {
    const key = [
      str(event.source_type),
      str(event.event_type),
      str(event.algorithm),
      str(event.host),
      str(event.observed_at),
    ].join('|')
    seen.set(key, (seen.get(key) || 0) + 1)
  }
  const duplicates = [...seen.values()].reduce((sum, count) => sum + Math.max(0, count - 1), 0)
  // Flag the surplus copies so duplication lowers the score like any other
  // defect, without double-penalising the first (legitimate) occurrence.
  const dupKeys = new Set([...seen.entries()].filter(([, count]) => count > 1).map(([key]) => key))
  issues_flagRows(
    runtimeEvents,
    (event) =>
      dupKeys.has([str(event.source_type), str(event.event_type), str(event.algorithm), str(event.host), str(event.observed_at)].join('|')),
    'rt',
  )
  add({
    id: 'duplicate-ingestion',
    label: 'Duplicate event rows',
    count: duplicates,
    examined: runtimeEvents.length,
    severity: duplicates > runtimeEvents.length / 4 ? 'high' : 'medium',
    consequence:
      'The same observation stored more than once inflates every count derived from this table until a consumer de-duplicates it.',
    remediation: 'Enable idempotent ingestion keys on the collector, or add a uniqueness constraint on (source, event, host, observed_at).',
  })

  /* ---- completeness ------------------------------------------------ */
  const noAlgorithm = issues_flagRows(
    runtimeEvents,
    (event) => !str(event.algorithm) && !str(event.cipher_suite) && !str(event.tls_version) && !str(event.key_exchange_algorithm),
    'rt',
  )
  add({
    id: 'no-primitive',
    label: 'Events naming no cryptographic primitive',
    count: noAlgorithm,
    examined: runtimeEvents.length,
    severity: 'low',
    consequence: 'These rows carry no algorithm, so they contribute to activity counts but to no posture verdict.',
    remediation: 'Check the collector module that emits them — an event with no primitive usually means a parse that failed silently.',
  })

  const noTimestamp = issues_flagRows([...runtimeEvents, ...evidence], (row) => !dateMs(row.observed_at) && !dateMs(row.created_at), 'any')
  add({
    id: 'no-timestamp',
    label: 'Rows with no usable timestamp',
    count: noTimestamp,
    examined,
    severity: 'medium',
    consequence: 'Rows without a time cannot be placed on any timeline and are invisible to freshness checks.',
    remediation: 'Ensure the collector stamps `observed_at` before transmission.',
  })

  // Score = share of examined rows carrying NO defect at all.
  return {
    measured: true,
    score: clamp(percentOf(Math.max(0, examined - flagged.size), examined)),
    issues: issues.sort((a, b) => b.percent - a.percent),
    rowsExamined: examined,
  }
}

/* ================================================================== */
/* Coverage                                                            */
/* ================================================================== */

function buildCoverage(input: {
  assets: Array<{ id: string; name: string; environment: string }>
  rows: Record<SourceKey, Row[]>
  now: number
}): TelemetryCoverage {
  const { assets, rows, now } = input

  const contributing: Array<{ key: SourceKey; label: string; time: string[] }> = [
    { key: 'runtime_crypto_events', label: 'Runtime', time: ['observed_at', 'created_at'] },
    { key: 'crypto_inventory', label: 'Inventory', time: ['discovered_at', 'created_at'] },
    { key: 'pqc_scan_results', label: 'Scan', time: ['created_at'] },
    { key: 'certificates', label: 'Certificates', time: ['updated_at', 'created_at'] },
    { key: 'crypto_exposures', label: 'Exposures', time: ['updated_at', 'created_at'] },
  ]

  const byAsset = new Map<string, { sources: Set<string>; events: number; lastMs: number; lastRuntimeMs: number }>()
  const knownAssets = new Set(assets.map((asset) => asset.id))
  let unattributed = 0
  let considered = 0

  for (const entry of contributing) {
    for (const row of rows[entry.key] ?? []) {
      considered += 1
      const assetId = str(row.asset_id)
      if (!knownAssets.has(assetId)) {
        unattributed += 1
        continue
      }
      const bucket = byAsset.get(assetId) ?? { sources: new Set<string>(), events: 0, lastMs: 0, lastRuntimeMs: 0 }
      bucket.sources.add(entry.label)
      bucket.events += 1
      for (const column of entry.time) {
        const ms = dateMs(row[column])
        if (ms > bucket.lastMs) bucket.lastMs = ms
      }
      if (entry.key === 'runtime_crypto_events' && isRuntimeOperationObservation(row)) {
        const observed = dateMs(row.observed_at)
        if (observed <= now) bucket.lastRuntimeMs = Math.max(bucket.lastRuntimeMs, observed)
      }
      byAsset.set(assetId, bucket)
    }
  }

  const records: CoverageRecord[] = assets.map((asset) => {
    const bucket = byAsset.get(asset.id)
    const lastMs = bucket?.lastMs ?? 0
    const ageMs = lastMs ? now - lastMs : null

    let health: HealthState
    if (!bucket) health = 'absent'
    else if (ageMs === null) health = 'degraded'
    else if (bucket.lastRuntimeMs > 0 && now - bucket.lastRuntimeMs <= DAY) health = 'healthy'
    else if (ageMs <= 7 * DAY) health = 'stale'
    else health = 'silent'

    return {
      assetId: asset.id,
      assetName: asset.name,
      environment: asset.environment,
      sources: bucket ? [...bucket.sources] : [],
      events: bucket?.events ?? 0,
      lastEvidenceAt: lastMs ? new Date(lastMs).toISOString() : null,
      health,
    }
  })

  const reporting = records.filter((record) => record.health === 'healthy').length
  return {
    assetsTotal: assets.length,
    assetsReporting: reporting,
    assetsSilent: assets.length - reporting,
    coveragePercent: percentOf(reporting, Math.max(1, assets.length)),
    records: records.sort((a, b) => a.events - b.events),
    unattributedEvents: unattributed,
    unattributedPercent: percentOf(unattributed, Math.max(1, considered)),
  }
}

/* ================================================================== */
/* Findings                                                            */
/* ================================================================== */

function buildFindings(input: {
  fleet: CollectorFleet
  sources: SourceHealth[]
  quality: SignalQuality
  coverage: TelemetryCoverage
  ingestion: IngestionLag
  now: number
}): PipelineFinding[] {
  const findings: PipelineFinding[] = []

  /* ---- collectors --------------------------------------------------- */
  for (const collector of input.fleet.collectors) {
    if (collector.health === 'healthy') continue
    findings.push({
      id: `pipeline:collector:${collector.id}`,
      title: `Collector ${collector.health}: ${collector.name}`,
      severity: collector.health === 'silent' ? 'critical' : 'high',
      stage: 'collection',
      detail: collector.healthReason,
      observed: `status "${collector.reportedStatus}" · ${collector.heartbeatsReceived} heartbeat(s) · ${collector.eventsAttributed} attributed event(s)`,
      remediation:
        collector.heartbeatsReceived === 0
          ? 'Check the collector is running and can reach the ingest endpoint; re-run the installer if it never registered.'
          : 'Restart the collector and confirm outbound connectivity to the ingest endpoint.',
      affects: ['Runtime Crypto Intelligence', 'TLS Telemetry', 'Encryption Monitoring'],
      actionHref: '/downloads',
      actionLabel: 'Agent Center',
    })
  }

  if (input.fleet.measured && input.fleet.heartbeatsTotal === 0) {
    findings.push({
      id: 'pipeline:no-heartbeats',
      title: 'No collector heartbeat has ever been received',
      severity: 'high',
      stage: 'collection',
      detail:
        'Collectors are registered but the heartbeat channel has produced nothing, so availability cannot be monitored and an outage would pass unnoticed.',
      observed: `${input.fleet.total} collector(s) registered · 0 heartbeat rows`,
      remediation: 'Confirm the collector build supports heartbeats and that its outbound path to the ingest endpoint is open.',
      affects: ['Agent Collector Console', 'every freshness indicator in the platform'],
      actionHref: '/dashboard/agents',
      actionLabel: 'Agents Collector',
    })
  }

  if (input.fleet.unattributableEvents > 0) {
    findings.push({
      id: 'pipeline:unattributable',
      title: 'Collector events arriving without a collector id',
      severity: 'high',
      stage: 'attribution',
      detail:
        'Evidence is being accepted from a collector-class source that stamps no agent id. It cannot be traced back to the collector that produced it, so a faulty or compromised collector cannot be isolated from its output.',
      observed: `${input.fleet.unattributableEvents} event(s)${input.fleet.unregisteredSources.length ? ` from ${input.fleet.unregisteredSources.join(', ')}` : ''}`,
      remediation: 'Upgrade the collector so it stamps its agent id, and re-enrol it if one was never issued.',
      affects: ['Collector fleet health', 'audit traceability'],
      actionHref: '/downloads',
      actionLabel: 'Agent Center',
    })
  }

  /* ---- sources ------------------------------------------------------ */
  for (const source of input.sources) {
    if (source.health === 'healthy') continue
    if (source.health === 'absent') {
      findings.push({
        id: `pipeline:absent:${source.key}`,
        title: `No data from ${source.label}`,
        severity: 'medium',
        stage: 'freshness',
        detail: source.detail,
        observed: '0 rows',
        remediation: `Connect the source that feeds ${source.label}, or treat every downstream zero as unmeasured.`,
        affects: source.feeds,
        actionHref: null,
        actionLabel: null,
      })
      continue
    }
    findings.push({
      id: `pipeline:stale:${source.key}`,
      title: `${source.label} is ${source.health}`,
      severity: source.health === 'silent' ? 'high' : 'medium',
      stage: 'freshness',
      detail: source.detail,
      observed: `newest row ${source.ageMs !== null ? formatDuration(source.ageMs) : 'unknown'} old · threshold ${formatDuration(source.thresholdMs)}`,
      remediation: 'Re-run collection for this source, or widen the freshness window if this cadence is expected.',
      affects: source.feeds,
      actionHref: '/dashboard/scanner',
      actionLabel: 'Run a scan',
    })
  }

  /* ---- quality ------------------------------------------------------ */
  for (const issue of input.quality.issues) {
    if (issue.severity === 'low') continue
    findings.push({
      id: `pipeline:quality:${issue.id}`,
      title: issue.label,
      severity: issue.severity,
      stage: 'quality',
      detail: issue.consequence,
      observed: `${issue.count} of ${issue.examined} row(s) — ${issue.percent}%`,
      remediation: issue.remediation,
      affects: ['every dashboard reading this source'],
      actionHref: null,
      actionLabel: null,
    })
  }

  /* ---- coverage ----------------------------------------------------- */
  if (input.coverage.assetsSilent > 0) {
    findings.push({
      id: 'pipeline:silent-assets',
      title: `${input.coverage.assetsSilent} asset(s) producing no telemetry`,
      severity: input.coverage.assetsSilent >= input.coverage.assetsTotal ? 'high' : 'medium',
      stage: 'collection',
      detail:
        'These assets appear in the inventory but no source has produced evidence for them. Their posture on every other dashboard is an absence of findings, not a clean result.',
      observed: `${input.coverage.assetsSilent} of ${input.coverage.assetsTotal} asset(s)`,
      remediation: 'Deploy a collector on them or include them in the next authorized scan.',
      affects: ['Quantum Readiness', 'Assets', 'Migration Planner'],
      actionHref: '/dashboard/scanner',
      actionLabel: 'Run a scan',
    })
  }

  /* ---- ingestion ---------------------------------------------------- */
  if (input.ingestion.measured && input.ingestion.p95Ms !== null && input.ingestion.p95Ms > 60_000) {
    findings.push({
      id: 'pipeline:ingest-lag',
      title: 'Ingestion lag above one minute at p95',
      severity: 'medium',
      stage: 'ingestion',
      detail:
        'Evidence is taking noticeably longer to persist than to observe. Live views will trail reality by roughly this margin.',
      observed: `p50 ${formatDuration(input.ingestion.p50Ms ?? 0)} · p95 ${formatDuration(input.ingestion.p95Ms)}`,
      remediation: 'Check collector batching intervals and ingest-endpoint latency.',
      affects: ['every "live" indicator in the platform'],
      actionHref: null,
      actionLabel: null,
    })
  }

  if (input.ingestion.negativeSamples > 0) {
    findings.push({
      id: 'pipeline:clock-skew',
      title: 'Collector clock skew detected',
      severity: 'medium',
      stage: 'ingestion',
      detail:
        'Some rows were persisted at a time earlier than they were observed, which means a collector clock disagrees with the platform. Timeline ordering and freshness checks are affected.',
      observed: `${input.ingestion.negativeSamples} row(s) with negative lag`,
      remediation: 'Enable NTP on the reporting hosts.',
      affects: ['all timelines', 'freshness verdicts'],
      actionHref: null,
      actionLabel: null,
    })
  }

  const rank: Record<Severity, number> = { critical: 4, high: 3, medium: 2, low: 1 }
  return findings.sort((a, b) => rank[b.severity] - rank[a.severity])
}

/* ================================================================== */
/* Presentation helpers                                                */
/* ================================================================== */

export function formatDuration(ms: number): string {
  const value = Math.abs(ms)
  if (value < 1000) return `${Math.round(value)}ms`
  if (value < MINUTE) return `${(value / 1000).toFixed(value < 10_000 ? 1 : 0)}s`
  if (value < HOUR) return `${Math.round(value / MINUTE)}m`
  if (value < DAY) return `${Math.round(value / HOUR)}h`
  return `${Math.round(value / DAY)}d`
}

function headlineFor(input: {
  healthState: HealthState
  fleet: CollectorFleet
  sources: SourceHealth[]
  coverage: TelemetryCoverage
  quality: SignalQuality
}): string {
  const absent = input.sources.filter((source) => source.health === 'absent').length
  const stale = input.sources.filter((source) => source.health === 'stale' || source.health === 'silent').length

  if (input.healthState === 'healthy') {
    return 'Collectors are reporting, sources are fresh and evidence is attributable. Figures elsewhere can be read at face value.'
  }
  if (!input.fleet.measured) {
    return 'No collector is registered. Everything the platform shows comes from scans alone, so nothing is continuously monitored.'
  }
  if (input.fleet.healthy === 0) {
    return `No collector is currently reporting${stale ? ` and ${stale} source(s) have gone stale` : ''}. Live views elsewhere are showing history, not current state.`
  }
  if (absent >= input.sources.length / 2) {
    return `${absent} of ${input.sources.length} sources have produced nothing. Zeros on other dashboards are largely unmeasured rather than clean.`
  }
  return `Pipeline is degraded: ${stale} stale source(s), ${input.coverage.assetsSilent} silent asset(s), signal quality ${input.quality.score}%.`
}
