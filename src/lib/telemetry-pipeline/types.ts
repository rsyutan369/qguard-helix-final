/**
 * Telemetry pipeline intelligence — the model behind Runtime Telemetry.
 *
 * Every other dashboard in QGuard Helix answers a question ABOUT the estate.
 * This one answers a question about the dashboards themselves: how complete,
 * how fresh and how trustworthy is the evidence they are all reading?
 *
 * It deliberately does not restate Runtime Cryptographic Intelligence
 * (`/dashboard/runtime-crypto-intel`), which owns "what cryptography is running
 * and is it quantum-safe". This module owns the layer beneath: collector
 * health, ingestion lag, source freshness, signal quality and coverage. When a
 * figure elsewhere looks wrong, this is the page that explains why.
 *
 * Counting rule: a count here is always of ROWS IN A NAMED TABLE. The page this
 * replaced summed a flattened array built from ~25 tables and reported 593
 * "keys" for a tenant holding none.
 */

/* ------------------------------------------------------------------ */
/* Shared vocabulary                                                   */
/* ------------------------------------------------------------------ */

import type { SourceRead } from '@/lib/source-read'

export type HealthState = 'healthy' | 'degraded' | 'stale' | 'silent' | 'absent' | 'unavailable'

export type Severity = 'critical' | 'high' | 'medium' | 'low'

/** A telemetry source the platform reads. */
export type SourceKey =
  | 'runtime_crypto_events'
  | 'scanner_evidence'
  | 'scanner_alerts'
  | 'crypto_inventory'
  | 'pqc_scan_results'
  | 'crypto_exposures'
  | 'certificates'
  | 'generated_keys'
  | 'security_events'
  | 'agent_heartbeats'
  | 'migration_jobs'
  | 'vault_files'

/* ------------------------------------------------------------------ */
/* Collector fleet                                                     */
/* ------------------------------------------------------------------ */

export interface CollectorRecord {
  id: string
  name: string
  hostname: string
  platform: string
  /** Status as recorded on the agent row. */
  reportedStatus: string
  /** Health derived from actual evidence, which can disagree with the above. */
  health: HealthState
  /** Why `health` differs from `reportedStatus`, when it does. */
  healthReason: string

  lastSeenAt: string | null
  /** Milliseconds since the collector last produced anything at all. */
  silentForMs: number | null

  heartbeatsReceived: number
  lastHeartbeatAt: string | null
  /** Events this collector can be shown to have produced (`agent_id` match). */
  eventsAttributed: number

  enrolledAt: string | null
  environment: string
  version: string
}

export interface CollectorFleet {
  /** True when the tenant has registered any collector at all. */
  measured: boolean
  collectors: CollectorRecord[]
  total: number
  healthy: number
  degraded: number
  silent: number
  /** Heartbeat rows across the fleet. Zero means the channel has never run. */
  heartbeatsTotal: number
  /**
   * Events whose `source_type` names a collector class but which carry no
   * `agent_id`, so they cannot be attributed to any registered collector.
   * A real integrity gap, not a rounding artifact.
   */
  unattributableEvents: number
  /** Source types seen on events that match no registered collector. */
  unregisteredSources: string[]
}

/* ------------------------------------------------------------------ */
/* Ingestion                                                           */
/* ------------------------------------------------------------------ */

/**
 * Lag between when a collector OBSERVED something and when the platform
 * PERSISTED it. Computed per event from real columns; never modelled.
 */
export interface IngestionLag {
  /** True when at least one row carried both timestamps. */
  measured: boolean
  samples: number
  p50Ms: number | null
  p95Ms: number | null
  maxMs: number | null
  /** Rows whose persisted time precedes their observed time — clock skew. */
  negativeSamples: number
  bySource: Array<{ source: string; samples: number; p50Ms: number; p95Ms: number; maxMs: number }>
}

export interface ThroughputPoint {
  label: string
  date: string
  /** Rows persisted that day, per source. */
  bySource: Record<string, number>
  total: number
}

/* ------------------------------------------------------------------ */
/* Source health                                                       */
/* ------------------------------------------------------------------ */

export interface SourceHealth {
  key: SourceKey
  label: string
  /** What this source feeds, so a stale row shows its blast radius. */
  feeds: string[]
  rows: number
  health: HealthState
  lastEventAt: string | null
  ageMs: number | null
  /** The staleness threshold this source is judged against, in ms. */
  thresholdMs: number
  /** Plain statement of what the health verdict means for the reader. */
  detail: string
  /** True when the row cap was reached, so `rows` is a lower bound. */
  truncated: boolean
}

/* ------------------------------------------------------------------ */
/* Signal quality                                                      */
/* ------------------------------------------------------------------ */

export interface QualityIssue {
  id: string
  label: string
  /** Rows exhibiting the issue. */
  count: number
  /** Rows examined — the denominator, always published beside the count. */
  examined: number
  percent: number
  severity: Severity
  /** What goes wrong downstream because of it. */
  consequence: string
  /** What the operator can do. */
  remediation: string
}

export interface SignalQuality {
  measured: boolean
  /** 0-100. Share of examined rows carrying no quality issue. */
  score: number
  issues: QualityIssue[]
  rowsExamined: number
}

/* ------------------------------------------------------------------ */
/* Coverage                                                            */
/* ------------------------------------------------------------------ */

export interface CoverageRecord {
  assetId: string
  assetName: string
  environment: string
  /** Sources that have produced evidence for this asset. */
  sources: string[]
  events: number
  lastEvidenceAt: string | null
  health: HealthState
}

export interface TelemetryCoverage {
  assetsTotal: number
  assetsReporting: number
  assetsSilent: number
  coveragePercent: number
  records: CoverageRecord[]
  /** Events carrying no asset binding — real evidence, no owner. */
  unattributedEvents: number
  unattributedPercent: number
}

/* ------------------------------------------------------------------ */
/* Findings                                                            */
/* ------------------------------------------------------------------ */

export interface PipelineFinding {
  id: string
  title: string
  severity: Severity
  /** Which part of the pipeline is at fault. */
  stage: 'collection' | 'ingestion' | 'attribution' | 'freshness' | 'quality'
  detail: string
  /** The measured value that triggered it. */
  observed: string
  remediation: string
  /** Dashboards degraded while this is open. */
  affects: string[]
  actionHref: string | null
  actionLabel: string | null
}

/* ------------------------------------------------------------------ */
/* Posture                                                             */
/* ------------------------------------------------------------------ */

export interface PipelinePosture {
  /** 0-100 composite of collection, freshness, attribution and quality. */
  pipelineHealthScore: number
  healthState: HealthState
  /** One sentence stating what the score means. */
  headline: string

  collectorsOnline: number
  collectorsTotal: number
  connectorsActive: number
  connectorsTotal: number

  eventsLast24h: number
  eventsLast7d: number

  ingestionP50Ms: number | null
  ingestionP95Ms: number | null

  sourcesHealthy: number
  sourcesTotal: number
  sourcesAbsent: number

  coveragePercent: number
  qualityScore: number

  /** Freshest and stalest source, so the range is visible at a glance. */
  freshestSource: string | null
  stalestSource: string | null
  stalestAgeMs: number | null
}

/* ------------------------------------------------------------------ */
/* The model                                                           */
/* ------------------------------------------------------------------ */

export interface TelemetryPipelineIntelligence {
  generatedAt: string
  latestEvidenceAt: string | null
  hasData: boolean
  reads: SourceRead[]

  posture: PipelinePosture
  fleet: CollectorFleet
  ingestion: IngestionLag
  throughput: ThroughputPoint[]
  sources: SourceHealth[]
  quality: SignalQuality
  coverage: TelemetryCoverage
  findings: PipelineFinding[]

  /** Row counts actually consulted, for the provenance footer. */
  sourceCounts: Record<string, number>
  truncated: boolean
}
