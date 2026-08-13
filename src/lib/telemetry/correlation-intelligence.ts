/**
 * Telemetry Correlation — the pure derivation engine.
 *
 * ── What was wrong ─────────────────────────────────────────────────────────
 * The implementation this replaces published
 *
 *     correlationScore = clamp(52 + coverage*0.35 + freshness + min(18, sources*2) - penalty)
 *
 * The constant 52 is a floor. A tenant with no agents, no connectors, no
 * scanner evidence and no runtime telemetry — a tenant QGuard Helix could see
 * nothing at all about — scored 52/100 and read "Needs Attention". Absence of
 * telemetry rendered as mediocre telemetry, which is the most dangerous
 * possible reading: it tells an operator the pipeline is working badly when in
 * fact it is not working.
 *
 * ── What correlation is actually for ───────────────────────────────────────
 * Correlation earns its place by answering questions a single source cannot:
 *
 *   COVERAGE      which assets does any telemetry see at all, and which are
 *                 completely invisible?
 *   CORROBORATION which observations did two independent sources confirm?
 *   CONFLICT      where do two sources DISAGREE about the same asset's
 *                 cryptography? That is the finding only correlation can
 *                 produce, and it is the reason this page exists.
 *   FRESHNESS     which sources have gone quiet, so their "clean" reading is
 *                 stale rather than reassuring?
 *
 * ── The rule ───────────────────────────────────────────────────────────────
 * NO SCORE WITHOUT SOURCES. Every score here is `null` until at least one
 * telemetry source has reported, and coverage is measured against the real
 * asset inventory rather than against whatever happened to report.
 *
 * Pure and dependency-free so the server, the browser and
 * `tools/telemetry-correlation-check.ts` all read one model.
 */

import {
  EVIDENCE_UNAVAILABLE,
  str,
  type AssetMigrationRecord,
  type Row,
} from '@/lib/migration/asset-intelligence'
import { analyzeCryptoObservation, type QuantumClass } from '@/lib/crypto/suite-anatomy'

/* ================================================================== */
/* Vocabulary                                                          */
/* ================================================================== */

export type SourceKind = 'scanner' | 'runtime-agent' | 'cloud-connector' | 'scan-session'

export type SourceHealth = 'reporting' | 'stale' | 'silent'

/** How many independent sources saw a given asset. */
export type CoverageTier = 'corroborated' | 'single-source' | 'blind-spot'

/* ================================================================== */
/* Model                                                               */
/* ================================================================== */

export interface TelemetrySource {
  id: string
  name: string
  kind: SourceKind
  kindLabel: string
  health: SourceHealth
  /** null when the source has never reported. */
  lastSeenAt: string | null
  observations: number
  assetsObserved: number
  detail: string
}

export interface CorrelatedObservation {
  id: string
  assetId: string | null
  assetName: string
  environment: string
  algorithm: string
  /** Verdict from the shared decomposer, per source. */
  quantumClass: QuantumClass
  sources: string[]
  sourceCount: number
  observations: number
  firstSeenAt: string | null
  lastSeenAt: string | null
  href: string
}

export interface CorrelationConflict {
  id: string
  assetId: string | null
  assetName: string
  environment: string
  /** What each source reported. */
  readings: Array<{ source: string; algorithm: string; quantumClass: QuantumClass; observedAt: string | null }>
  severity: 'critical' | 'high' | 'medium'
  summary: string
  why: string
  recommendedAction: string
  href: string
}

export interface CoverageRow {
  key: CoverageTier
  label: string
  glyph: string
  count: number
  percent: number
  detail: string
}

export interface BlindSpot {
  assetId: string
  assetName: string
  type: string
  environment: string
  businessCriticality: string
  internetFacing: boolean
  why: string
  href: string
}

export interface CorrelationScore {
  /** null until at least one source has reported. Never a floor. */
  score: number | null
  level: string
  statement: string
  basis: string
}

export interface CorrelationIntelligence {
  generatedAt: string
  hasTelemetry: boolean
  coverageScore: CorrelationScore
  kpis: {
    activeSources: number
    totalSources: number
    assetsCovered: number
    assetsTotal: number
    corroboratedAssets: number
    blindSpots: number
    conflicts: number
  }
  sources: TelemetrySource[]
  coverage: CoverageRow[]
  observations: CorrelatedObservation[]
  conflicts: CorrelationConflict[]
  blindSpots: BlindSpot[]
  filters: { environments: string[]; sources: string[] }
  evidence: { sources: string[]; note: string }
}

/* ================================================================== */
/* Inputs                                                              */
/* ================================================================== */

export interface CorrelationInputs {
  assets: AssetMigrationRecord[]
  /** Raw scanner evidence rows — one telemetry channel. */
  scannerEvidence: Row[]
  /** Runtime crypto events — a second, independent channel. */
  runtimeEvents: Row[]
  /** Discovered cryptographic inventory — the scan channel. */
  cryptoInventory: Row[]
  scannerAgents: Row[]
  connectorAccounts: Row[]
  scanSessions: Row[]
  now?: number
}

/* ================================================================== */
/* Helpers                                                             */
/* ================================================================== */

const ms = (value: unknown): number => {
  const parsed = Date.parse(str(value))
  return Number.isFinite(parsed) ? parsed : 0
}

const iso = (value: unknown): string | null => {
  const text = str(value)
  return text && Number.isFinite(Date.parse(text)) ? new Date(text).toISOString() : null
}

const pct = (part: number, total: number) => (total > 0 ? Math.round((part / total) * 100) : 0)

const STALE_MS = 24 * 60 * 60_000
const REPORTING_MS = 60 * 60_000

const KIND_LABEL: Record<SourceKind, string> = {
  scanner: 'Scanner',
  'runtime-agent': 'Runtime Agent',
  'cloud-connector': 'Cloud Connector',
  'scan-session': 'Scan Session',
}

function healthFor(lastSeen: number, now: number): SourceHealth {
  if (!lastSeen) return 'silent'
  const age = now - lastSeen
  if (age <= REPORTING_MS) return 'reporting'
  if (age <= STALE_MS) return 'stale'
  return 'silent'
}

/** The identity two channels must agree on to be "the same observation". */
function observationKey(assetLabel: string, algorithm: string): string {
  return `${assetLabel.trim().toLowerCase()}::${algorithm.trim().toLowerCase()}`
}

/* ================================================================== */
/* Engine                                                              */
/* ================================================================== */

export function buildCorrelationIntelligence(inputs: CorrelationInputs): CorrelationIntelligence {
  const now = inputs.now ?? Date.now()

  const assetById = new Map(inputs.assets.map((asset) => [asset.id, asset]))
  const assetByName = new Map<string, AssetMigrationRecord>()
  for (const asset of inputs.assets) {
    if (asset.name) assetByName.set(asset.name.toLowerCase(), asset)
    if (asset.hostname) assetByName.set(asset.hostname.toLowerCase(), asset)
  }
  const resolveAsset = (row: Row): AssetMigrationRecord | null => {
    const byId = str(row.asset_id) ? assetById.get(str(row.asset_id)) : undefined
    if (byId) return byId
    const name = str(row.asset_name).toLowerCase() || str(row.host).toLowerCase() || str(row.target).toLowerCase()
    return (name ? assetByName.get(name) : undefined) ?? null
  }
  const labelFor = (row: Row, asset: AssetMigrationRecord | null): string =>
    asset?.name || str(row.asset_name) || str(row.host) || str(row.target) || ''

  /* ---- Channel normalisation ---------------------------------------- */
  interface Reading {
    channel: string
    assetLabel: string
    assetId: string | null
    algorithm: string
    quantumClass: QuantumClass
    at: number
  }

  const readings: Reading[] = []

  for (const row of inputs.scannerEvidence) {
    const asset = resolveAsset(row)
    const label = labelFor(row, asset)
    const algorithm = str(row.observed_algorithm) || str(row.protocol)
    if (!label || !algorithm) continue
    readings.push({
      channel: 'Scanner Evidence',
      assetLabel: label,
      assetId: asset?.id ?? null,
      algorithm,
      quantumClass: analyzeCryptoObservation({ algorithm, protocol: str(row.protocol) }).quantumClass,
      at: ms(row.observed_at || row.created_at),
    })
  }

  for (const row of inputs.runtimeEvents) {
    const asset = resolveAsset(row)
    const label = labelFor(row, asset)
    // Runtime carries the key exchange in its own column; the suite name alone
    // does not decide the verdict for TLS 1.3.
    const algorithm = str(row.key_exchange_algorithm) || str(row.algorithm) || str(row.cipher_suite)
    if (!label || !algorithm) continue
    readings.push({
      channel: 'Runtime Telemetry',
      assetLabel: label,
      assetId: asset?.id ?? null,
      algorithm,
      quantumClass: analyzeCryptoObservation({ algorithm, protocol: str(row.protocol) }).quantumClass,
      at: ms(row.observed_at || row.created_at),
    })
  }

  for (const row of inputs.cryptoInventory) {
    const asset = resolveAsset(row)
    const label = labelFor(row, asset) || (str(row.asset_id) ? assetById.get(str(row.asset_id))?.name ?? '' : '')
    const algorithm = str(row.algorithm)
    if (!label || !algorithm) continue
    readings.push({
      channel: 'CBOM Inventory',
      assetLabel: label,
      assetId: asset?.id ?? (str(row.asset_id) || null),
      algorithm,
      quantumClass: analyzeCryptoObservation({ algorithm, protocol: str(row.protocol), itemType: str(row.item_type) }).quantumClass,
      at: ms(row.discovered_at || row.created_at),
    })
  }

  /* ---- Correlated observations --------------------------------------- */
  const observationIndex = new Map<string, { reading: Reading; channels: Set<string>; count: number; first: number; last: number }>()
  for (const reading of readings) {
    const key = observationKey(reading.assetLabel, reading.algorithm)
    const existing = observationIndex.get(key)
    if (existing) {
      existing.channels.add(reading.channel)
      existing.count += 1
      existing.first = Math.min(existing.first || reading.at, reading.at)
      existing.last = Math.max(existing.last, reading.at)
    } else {
      observationIndex.set(key, { reading, channels: new Set([reading.channel]), count: 1, first: reading.at, last: reading.at })
    }
  }

  const observations: CorrelatedObservation[] = Array.from(observationIndex.entries())
    .map(([key, entry]) => {
      const asset = entry.reading.assetId ? assetById.get(entry.reading.assetId) : assetByName.get(entry.reading.assetLabel.toLowerCase())
      return {
        id: key,
        assetId: entry.reading.assetId,
        assetName: entry.reading.assetLabel,
        environment: asset?.environment || 'unspecified',
        algorithm: entry.reading.algorithm,
        quantumClass: entry.reading.quantumClass,
        sources: Array.from(entry.channels),
        sourceCount: entry.channels.size,
        observations: entry.count,
        firstSeenAt: entry.first ? new Date(entry.first).toISOString() : null,
        lastSeenAt: entry.last ? new Date(entry.last).toISOString() : null,
        href: entry.reading.assetId ? `/dashboard/migration-planner?asset=${encodeURIComponent(entry.reading.assetId)}` : '/dashboard/cbom',
      }
    })
    .sort((a, b) => b.sourceCount - a.sourceCount || b.observations - a.observations)

  /* ---- Conflicts: the finding only correlation can produce ------------ */
  const byAssetClass = new Map<string, Map<QuantumClass, Reading[]>>()
  for (const reading of readings) {
    // A conflict is only meaningful for the risk-bearing key agreement, so
    // observations whose class is `unknown` are not treated as disagreement —
    // "we could not classify it" is not the same as "we disagree".
    if (reading.quantumClass === 'unknown') continue
    const assetKey = reading.assetLabel.trim().toLowerCase()
    const classes = byAssetClass.get(assetKey) ?? new Map<QuantumClass, Reading[]>()
    classes.set(reading.quantumClass, [...(classes.get(reading.quantumClass) ?? []), reading])
    byAssetClass.set(assetKey, classes)
  }

  const conflicts: CorrelationConflict[] = []
  for (const [assetKey, classes] of byAssetClass) {
    // Disagreement means two DIFFERENT channels reported different postures for
    // the same asset. One channel reporting both a safe and a vulnerable
    // primitive is normal (an asset runs several algorithms), so channel
    // diversity is required before anything is called a conflict.
    const hasVulnerable = classes.has('vulnerable')
    const hasSafeOrHybrid = classes.has('safe') || classes.has('hybrid')
    if (!hasVulnerable || !hasSafeOrHybrid) continue

    const vulnerableReadings = classes.get('vulnerable') ?? []
    const safeReadings = [...(classes.get('safe') ?? []), ...(classes.get('hybrid') ?? [])]
    const vulnerableChannels = new Set(vulnerableReadings.map((r) => r.channel))
    const safeChannels = new Set(safeReadings.map((r) => r.channel))
    const distinct = [...vulnerableChannels].some((channel) => !safeChannels.has(channel)) &&
      [...safeChannels].some((channel) => !vulnerableChannels.has(channel))
    if (!distinct) continue

    const sample = vulnerableReadings[0]
    const asset = sample.assetId ? assetById.get(sample.assetId) : assetByName.get(assetKey)
    const readingRows = [...vulnerableReadings.slice(0, 3), ...safeReadings.slice(0, 3)].map((r) => ({
      source: r.channel,
      algorithm: r.algorithm,
      quantumClass: r.quantumClass,
      observedAt: r.at ? new Date(r.at).toISOString() : null,
    }))

    // Runtime disagreeing with discovery is the most actionable case: it means
    // what is CONFIGURED and what is EXECUTING are not the same thing.
    const runtimeDisagrees = vulnerableChannels.has('Runtime Telemetry') && !safeChannels.has('Runtime Telemetry')
    conflicts.push({
      id: `conflict:${assetKey}`,
      assetId: sample.assetId,
      assetName: sample.assetLabel,
      environment: asset?.environment || 'unspecified',
      readings: readingRows,
      severity: runtimeDisagrees && asset?.internetFacing ? 'critical' : runtimeDisagrees ? 'high' : 'medium',
      summary: `Sources disagree about ${sample.assetLabel}`,
      why: runtimeDisagrees
        ? 'Runtime telemetry observed quantum-vulnerable cryptography on an asset that discovery reports as post-quantum. What is configured and what is actually executing are not the same.'
        : 'Independent telemetry channels report different cryptographic postures for this asset. One of them is looking at a surface the other is not.',
      recommendedAction: runtimeDisagrees
        ? 'Trust the runtime reading and investigate the gap — usually an un-migrated code path, a cached client or an intermediary.'
        : 'Re-scan the asset and compare which surfaces each channel actually covers.',
      href: sample.assetId ? `/dashboard/migration-planner?asset=${encodeURIComponent(sample.assetId)}` : '/dashboard/cbom',
    })
  }
  const CONFLICT_RANK = { critical: 0, high: 1, medium: 2 }
  conflicts.sort((a, b) => CONFLICT_RANK[a.severity] - CONFLICT_RANK[b.severity])

  /* ---- Sources --------------------------------------------------------- */
  const sources: TelemetrySource[] = []

  for (const agent of inputs.scannerAgents) {
    const lastSeen = ms(agent.last_seen_at)
    const observed = inputs.runtimeEvents.filter((event) => str(event.agent_id) === str(agent.id))
    sources.push({
      id: `agent:${str(agent.id)}`,
      name: str(agent.name) || str(agent.hostname) || 'Collector agent',
      kind: 'runtime-agent',
      kindLabel: KIND_LABEL['runtime-agent'],
      health: healthFor(lastSeen, now),
      lastSeenAt: iso(agent.last_seen_at),
      observations: observed.length,
      assetsObserved: new Set(observed.map((e) => str(e.asset_id) || str(e.asset_name)).filter(Boolean)).size,
      detail: str(agent.platform) || str(agent.hostname) || 'Runtime cryptographic collector',
    })
  }

  for (const connector of inputs.connectorAccounts) {
    const observed = inputs.runtimeEvents.filter((event) => str(event.connector_account_id) === str(connector.id))
    const lastSeen = observed.reduce((latest, event) => Math.max(latest, ms(event.observed_at || event.created_at)), 0)
    sources.push({
      id: `connector:${str(connector.id)}`,
      name: str(connector.provider) || 'Cloud connector',
      kind: 'cloud-connector',
      kindLabel: KIND_LABEL['cloud-connector'],
      health: str(connector.status).toLowerCase() === 'connected' ? healthFor(lastSeen || now, now) : 'silent',
      lastSeenAt: lastSeen ? new Date(lastSeen).toISOString() : null,
      observations: observed.length,
      assetsObserved: new Set(observed.map((e) => str(e.asset_id) || str(e.asset_name)).filter(Boolean)).size,
      detail: `Provider status: ${str(connector.status) || 'unknown'}`,
    })
  }

  const completedSessions = inputs.scanSessions.filter((session) => ms(session.completed_at) > 0)
  if (completedSessions.length) {
    const latest = completedSessions.reduce((acc, session) => Math.max(acc, ms(session.completed_at)), 0)
    sources.push({
      id: 'scanner:pqc',
      name: 'PQC Scanner',
      kind: 'scanner',
      kindLabel: KIND_LABEL.scanner,
      health: healthFor(latest, now),
      lastSeenAt: new Date(latest).toISOString(),
      observations: inputs.cryptoInventory.length + inputs.scannerEvidence.length,
      assetsObserved: new Set(
        [...inputs.cryptoInventory, ...inputs.scannerEvidence].map((row) => str(row.asset_id) || str(row.asset_name)).filter(Boolean),
      ).size,
      detail: `${completedSessions.length} completed scan session(s)`,
    })
  }

  sources.sort((a, b) => b.observations - a.observations)

  /* ---- Coverage --------------------------------------------------------- */
  const channelsByAsset = new Map<string, Set<string>>()
  for (const reading of readings) {
    const key = reading.assetLabel.trim().toLowerCase()
    const set = channelsByAsset.get(key) ?? new Set<string>()
    set.add(reading.channel)
    channelsByAsset.set(key, set)
  }

  const blindSpots: BlindSpot[] = inputs.assets
    .filter((asset) => {
      const byName = channelsByAsset.get(asset.name.toLowerCase())
      const byHost = asset.hostname ? channelsByAsset.get(asset.hostname.toLowerCase()) : undefined
      return !byName?.size && !byHost?.size
    })
    .map((asset) => ({
      assetId: asset.id,
      assetName: asset.name,
      type: asset.type,
      environment: asset.environment || 'unspecified',
      businessCriticality: asset.businessCriticality || 'unspecified',
      internetFacing: asset.internetFacing,
      why: 'No scanner evidence, runtime telemetry or cryptographic inventory has been recorded for this asset. Its cryptographic posture is unknown, not safe.',
      href: '/dashboard/scanner',
    }))
    .sort((a, b) => Number(b.internetFacing) - Number(a.internetFacing) || a.assetName.localeCompare(b.assetName))

  const totalAssets = inputs.assets.length
  const corroborated = inputs.assets.filter((asset) => {
    const set = channelsByAsset.get(asset.name.toLowerCase()) ?? (asset.hostname ? channelsByAsset.get(asset.hostname.toLowerCase()) : undefined)
    return (set?.size ?? 0) >= 2
  }).length
  const covered = totalAssets - blindSpots.length
  const singleSource = Math.max(0, covered - corroborated)

  const coverage: CoverageRow[] = [
    { key: 'corroborated', label: 'Corroborated', glyph: '✓', count: corroborated, percent: pct(corroborated, totalAssets), detail: 'Observed by two or more independent telemetry channels.' },
    { key: 'single-source', label: 'Single source', glyph: '◐', count: singleSource, percent: pct(singleSource, totalAssets), detail: 'Seen by exactly one channel — no independent confirmation.' },
    { key: 'blind-spot', label: 'Blind spot', glyph: '?', count: blindSpots.length, percent: pct(blindSpots.length, totalAssets), detail: 'No telemetry at all. Posture unknown, not safe.' },
  ]

  /* ---- Score ------------------------------------------------------------- */
  const activeSources = sources.filter((source) => source.health !== 'silent').length
  const hasTelemetry = readings.length > 0 || sources.length > 0
  const coverageScore = buildCoverageScore(hasTelemetry, totalAssets, covered, corroborated, sources, conflicts.length)

  return {
    generatedAt: new Date(now).toISOString(),
    hasTelemetry,
    coverageScore,
    kpis: {
      activeSources,
      totalSources: sources.length,
      assetsCovered: covered,
      assetsTotal: totalAssets,
      corroboratedAssets: corroborated,
      blindSpots: blindSpots.length,
      conflicts: conflicts.length,
    },
    sources,
    coverage,
    observations: observations.slice(0, 200),
    conflicts,
    blindSpots: blindSpots.slice(0, 50),
    filters: {
      environments: Array.from(new Set(observations.map((o) => o.environment).filter((v) => v && v !== 'unspecified'))).sort(),
      sources: Array.from(new Set(readings.map((r) => r.channel))).sort(),
    },
    evidence: {
      sources: ['Scanner Evidence', 'Runtime Crypto Telemetry', 'CBOM / Crypto Inventory', 'Collector Agents', 'Cloud Connectors'],
      note: hasTelemetry
        ? `${readings.length} observation(s) from ${new Set(readings.map((r) => r.channel)).size} independent channel(s) across ${covered} of ${totalAssets} asset(s). Cryptographic verdicts come from the shared cipher-suite decomposer, so a channel's reading here means the same thing it means on every other page.`
        : `${EVIDENCE_UNAVAILABLE}. No telemetry source has reported for this tenant.`,
    },
  }
}

/* ================================================================== */
/* Coverage score                                                      */
/* ================================================================== */

/**
 * Telemetry coverage: the share of the asset inventory that any channel can
 * actually see, weighted up for independent corroboration and down for stale
 * sources and unresolved conflicts.
 *
 * `null` when nothing has reported. There is no floor — the defect this
 * replaces added a constant 52, so an estate QGuard Helix was blind to scored
 * as merely mediocre.
 */
function buildCoverageScore(
  hasTelemetry: boolean,
  totalAssets: number,
  covered: number,
  corroborated: number,
  sources: TelemetrySource[],
  conflicts: number,
): CorrelationScore {
  if (!hasTelemetry) {
    return {
      score: null,
      level: 'No Telemetry',
      statement: 'No telemetry source has reported, so cryptographic coverage cannot be measured.',
      basis: 'A coverage score is only published once at least one source reports. An estate the platform cannot see is never scored as partially covered.',
    }
  }
  if (totalAssets === 0) {
    return {
      score: null,
      level: 'No Assets',
      statement: 'No assets have been discovered yet, so there is nothing to correlate telemetry against.',
      basis: 'Coverage is measured against the discovered asset inventory. With no inventory there is no denominator.',
    }
  }

  const coveragePct = (covered / totalAssets) * 100
  const corroborationPct = (corroborated / totalAssets) * 100
  const stale = sources.filter((source) => source.health !== 'reporting').length
  const stalePenalty = Math.min(15, stale * 5)
  const conflictPenalty = Math.min(10, conflicts * 5)

  // Coverage is the backbone; corroboration adds up to 25 points on top.
  const raw = coveragePct * 0.75 + corroborationPct * 0.25 - stalePenalty - conflictPenalty
  const score = Math.max(0, Math.min(100, Math.round(raw)))
  const level = score >= 90 ? 'Comprehensive' : score >= 70 ? 'Good' : score >= 40 ? 'Partial' : 'Limited'

  return {
    score,
    level,
    statement:
      covered === totalAssets
        ? `Every discovered asset is observed by at least one telemetry channel; ${corroborated} of ${totalAssets} are independently corroborated.`
        : `${covered} of ${totalAssets} discovered asset(s) are observed by at least one telemetry channel. ${totalAssets - covered} remain invisible.`,
    basis: `75% of the score is the share of discovered assets any channel can see, 25% is the share confirmed by two or more independent channels. Stale sources cost up to 15 points and unresolved conflicts up to 10. There is no baseline value — an estate with no telemetry is not scored at all.`,
  }
}

/* ================================================================== */
/* Filtering                                                           */
/* ================================================================== */

export interface CorrelationFilters {
  environment: string
  source: string
  tier: 'all' | 'corroborated' | 'single-source'
  search: string
}

export const EMPTY_CORRELATION_FILTERS: CorrelationFilters = {
  environment: 'all',
  source: 'all',
  tier: 'all',
  search: '',
}

export function filterObservations(rows: CorrelatedObservation[], filters: CorrelationFilters): CorrelatedObservation[] {
  const search = filters.search.trim().toLowerCase()
  return rows.filter((row) => {
    if (filters.environment !== 'all' && row.environment !== filters.environment) return false
    if (filters.source !== 'all' && !row.sources.includes(filters.source)) return false
    if (filters.tier === 'corroborated' && row.sourceCount < 2) return false
    if (filters.tier === 'single-source' && row.sourceCount !== 1) return false
    if (search) {
      const haystack = `${row.assetName} ${row.algorithm} ${row.sources.join(' ')}`.toLowerCase()
      if (!haystack.includes(search)) return false
    }
    return true
  })
}
