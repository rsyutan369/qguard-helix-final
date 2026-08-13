/**
 * Cryptographic Drift Detection — the pure derivation engine.
 *
 * ── What was wrong ─────────────────────────────────────────────────────────
 * The implementation this replaces did not measure drift. It read
 * `crypto_exposures`, `pqc_scan_results`, `security_events`, `migration_events`,
 * `compliance_evidence` and `vulnerabilities`, keyword-matched each row for
 * words like "drift", "legacy" or "policy", and relabelled whatever matched as
 * a drift event. Nothing was ever compared against anything. The page was the
 * vulnerabilities inventory wearing a different hat — same rows, different
 * noun — so a tenant whose cryptography had not changed in months still showed
 * a busy drift feed, and a tenant whose TLS silently downgraded last night saw
 * nothing new.
 *
 * ── What drift actually is ─────────────────────────────────────────────────
 * Drift is CHANGE FROM A KNOWN BASELINE. It requires two observations of the
 * same thing at two points in time. That gives this engine one hard
 * precondition and one hard rule:
 *
 *   PRECONDITION. Two completed scan sessions must exist. With one scan there
 *   is no baseline, so there is no drift — the engine reports "no baseline"
 *   rather than presenting the first scan's findings as if they were changes.
 *
 *   RULE. Planned change is not drift. A cryptographic change on an asset with
 *   a matching migration job is the migration working, and is reported as
 *   PLANNED. Counting it as drift turns every successful remediation into an
 *   alert and trains operators to ignore the page.
 *
 * ── The four delta classes ─────────────────────────────────────────────────
 *   REGRESSION   a new weakness appeared, or posture got worse. Unplanned.
 *   IMPROVEMENT  a weakness disappeared. Unplanned — worth confirming.
 *   PLANNED      the change matches an approved migration for that asset.
 *   PERSISTENT   present in both scans. Not drift; carried for context only.
 *
 * Pure and dependency-free so the server, the browser and
 * `tools/drift-check.ts` all read one model.
 */

import {
  EVIDENCE_UNAVAILABLE,

  str,
  type AssetMigrationRecord,
  type Row,
} from '@/lib/migration/asset-intelligence'
import { analyzeCryptoObservation } from '@/lib/crypto/suite-anatomy'

/* ================================================================== */
/* Vocabulary                                                          */
/* ================================================================== */

export type DriftClass = 'regression' | 'improvement' | 'planned' | 'coverage' | 'persistent'

export type DriftSource = 'scan-comparison' | 'runtime-downgrade' | 'certificate-change'

export type Severity = 'critical' | 'high' | 'medium' | 'low'

export const SEVERITY_RANK: Record<Severity, number> = { critical: 4, high: 3, medium: 2, low: 1 }

export function normalizeSeverity(value: unknown): Severity {
  const text = str(value).toLowerCase()
  if (text.includes('critical')) return 'critical'
  if (text.includes('high')) return 'high'
  if (text.includes('medium') || text.includes('moderate')) return 'medium'
  return 'low'
}

export const CLASS_LABEL: Record<DriftClass, string> = {
  regression: 'Regression',
  improvement: 'Improvement',
  planned: 'Planned change',
  coverage: 'Coverage change',
  persistent: 'Unchanged',
}

/* ================================================================== */
/* Model                                                               */
/* ================================================================== */

export interface DriftEvent {
  id: string
  driftClass: DriftClass
  source: DriftSource
  /** What changed, in plain language. */
  summary: string
  assetId: string | null
  assetName: string
  environment: string
  owner: string
  algorithm: string
  /** The value observed in the baseline scan. null when the item is new. */
  before: string | null
  /** The value observed in the current scan. null when the item disappeared. */
  after: string | null
  severity: Severity
  detectedAt: string | null
  /** Why this is (or is not) a problem. */
  why: string
  recommendedAction: string
  /** The evidence this classification rests on. */
  evidence: string[]
  /** Migration job that explains the change, when one does. */
  explainedBy: string | null
  href: string
}

export interface BaselineWindow {
  /** True only when two completed scans exist. Everything else depends on it. */
  available: boolean
  baselineSessionId: string | null
  baselineAt: string | null
  currentSessionId: string | null
  currentAt: string | null
  /** Completed scan sessions available to compare. */
  sessionsCompared: number
  totalSessions: number
  note: string
}

export interface DriftSummaryRow {
  key: DriftClass
  label: string
  glyph: string
  count: number
  percent: number
}

export interface AssetDriftRow {
  assetId: string | null
  assetName: string
  environment: string
  regressions: number
  improvements: number
  planned: number
  /** Net posture movement: negative is worse. */
  netChange: number
  worstSeverity: Severity | null
  href: string
}

export interface StabilityScore {
  /** null until a baseline exists. Never 100-from-nothing. */
  score: number | null
  level: string
  statement: string
  basis: string
}

export interface DriftIntelligence {
  generatedAt: string
  hasBaseline: boolean
  baseline: BaselineWindow
  stability: StabilityScore
  kpis: {
    regressions: number
    improvements: number
    planned: number
    unplannedChanges: number
    assetsChanged: number
    runtimeDowngrades: number
  }
  summary: DriftSummaryRow[]
  events: DriftEvent[]
  byAsset: AssetDriftRow[]
  /** Posture across the compared sessions — two points, honestly labelled. */
  postureDelta: {
    baselineFindings: number
    currentFindings: number
    delta: number
    baselineVulnerable: number
    currentVulnerable: number
  } | null
  filters: { environments: string[]; classes: DriftClass[] }
  evidence: { sources: string[]; note: string }
}

/* ================================================================== */
/* Inputs                                                              */
/* ================================================================== */

export interface DriftInputs {
  /** Completed scan sessions, any order. At least two are needed. */
  scanSessions: Row[]
  /** Graded findings carrying `scan_session_id`. */
  scanResults: Row[]
  /** Runtime events — `downgrade_detected` is first-hand drift evidence. */
  runtimeEvents: Row[]
  /** Migration jobs, used to separate planned change from drift. */
  migrationJobs: Row[]
  assets: AssetMigrationRecord[]
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

const CLASS_GLYPH: Record<DriftClass, string> = {
  regression: '●',
  improvement: '✓',
  planned: '◐',
  coverage: '◇',
  persistent: '·',
}

/**
 * Finding identity WITHIN a scan comparison: the same algorithm on the same
 * asset is the same item across sessions. Deliberately excludes the finding's
 * own row id and its narrative text — both change between scans even when the
 * underlying cryptography has not, and keying on either would report every
 * re-scan as wholesale change.
 */
function itemKey(assetLabel: string, algorithm: string): string {
  return `${assetLabel.trim().toLowerCase()}::${algorithm.trim().toLowerCase()}`
}

/** Is this algorithm quantum-vulnerable? One classifier, shared platform-wide. */
function isVulnerable(algorithm: string): boolean {
  return analyzeCryptoObservation({ algorithm }).quantumClass === 'vulnerable'
}

/* ================================================================== */
/* Engine                                                              */
/* ================================================================== */

export function buildDriftIntelligence(inputs: DriftInputs): DriftIntelligence {
  const now = inputs.now ?? Date.now()

  const assetByName = new Map<string, AssetMigrationRecord>()
  for (const asset of inputs.assets) {
    if (asset.name) assetByName.set(asset.name.toLowerCase(), asset)
    if (asset.hostname) assetByName.set(asset.hostname.toLowerCase(), asset)
  }
  const assetById = new Map(inputs.assets.map((asset) => [asset.id, asset]))
  const resolveAsset = (row: Row): AssetMigrationRecord | null => {
    const byId = str(row.asset_id) ? assetById.get(str(row.asset_id)) : undefined
    if (byId) return byId
    const name = str(row.asset_name).toLowerCase() || str(row.host).toLowerCase()
    return (name ? assetByName.get(name) : undefined) ?? null
  }

  /* ---- Baseline selection ------------------------------------------- */
  const completed = inputs.scanSessions
    .filter((session) => ms(session.completed_at) > 0)
    .sort((a, b) => ms(b.completed_at) - ms(a.completed_at))

  const current = completed[0] ?? null
  const previous = completed[1] ?? null
  const available = Boolean(current && previous)

  const baseline: BaselineWindow = {
    available,
    baselineSessionId: previous ? str(previous.id) : null,
    baselineAt: previous ? iso(previous.completed_at) : null,
    currentSessionId: current ? str(current.id) : null,
    currentAt: current ? iso(current.completed_at) : null,
    sessionsCompared: available ? 2 : completed.length,
    totalSessions: inputs.scanSessions.length,
    note: available
      ? 'Drift is measured by comparing the two most recent completed scans of this environment.'
      : completed.length === 1
        ? 'Only one completed scan exists. Drift needs two observations of the same estate — run a second scan to establish a baseline. The findings from the first scan are not drift.'
        : 'No completed scan has been recorded, so there is no baseline and no drift to measure.',
  }

  /* ---- Migration index: what change was PLANNED ---------------------- */
  interface PlannedChange { jobId: string; name: string; target: string; at: number; status: string }
  const plannedByAsset = new Map<string, PlannedChange[]>()
  for (const job of inputs.migrationJobs) {
    const assetId = str(job.asset_id)
    if (!assetId) continue
    const status = str(job.status).toLowerCase()
    if (!['completed', 'running', 'in-progress', 'in_progress'].includes(status)) continue
    plannedByAsset.set(assetId, [
      ...(plannedByAsset.get(assetId) ?? []),
      {
        jobId: str(job.id),
        name: str(job.name) || 'Migration job',
        target: str(job.target_algorithm),
        at: ms(job.completed_at || job.updated_at || job.created_at),
        status,
      },
    ])
  }

  const baselineAtMs = ms(previous?.completed_at)
  /**
   * A change counts as planned when an approved migration for the SAME asset
   * was active or completed inside the comparison window. Outside the window it
   * cannot explain a change that happened inside it.
   */
  const plannedExplanation = (assetId: string | null, algorithm: string): PlannedChange | null => {
    if (!assetId) return null
    const jobs = plannedByAsset.get(assetId) ?? []
    const inWindow = jobs.filter((job) => job.at >= baselineAtMs)
    if (!inWindow.length) return null
    const targeted = inWindow.find((job) => job.target && algorithm && (
      job.target.toLowerCase().includes(algorithm.toLowerCase()) ||
      algorithm.toLowerCase().includes(job.target.toLowerCase())
    ))
    return targeted ?? inWindow[0]
  }

  /* ---- Scan comparison ------------------------------------------------ */
  const events: DriftEvent[] = []

  interface Item { algorithm: string; severity: Severity; assetLabel: string; assetId: string | null; at: string | null; row: Row }
  const indexSession = (sessionId: string): Map<string, Item> => {
    const index = new Map<string, Item>()
    for (const result of inputs.scanResults) {
      if (str(result.scan_session_id) !== sessionId) continue
      const asset = resolveAsset(result)
      const algorithm = str(result.algorithm)
      if (!algorithm) continue
      const assetLabel = asset?.name || str(result.asset_name) || str(result.asset_id) || 'Unattributed'
      const key = itemKey(assetLabel, algorithm)
      const existing = index.get(key)
      const severity = normalizeSeverity(result.threat_level)
      // Keep the worst severity when a session records an item more than once.
      if (!existing || SEVERITY_RANK[severity] > SEVERITY_RANK[existing.severity]) {
        index.set(key, { algorithm, severity, assetLabel, assetId: asset?.id ?? (str(result.asset_id) || null), at: iso(result.created_at), row: result })
      }
    }
    return index
  }

  let postureDelta: DriftIntelligence['postureDelta'] = null

  if (available && current && previous) {
    const currentIndex = indexSession(str(current.id))
    const baselineIndex = indexSession(str(previous.id))

    postureDelta = {
      baselineFindings: baselineIndex.size,
      currentFindings: currentIndex.size,
      delta: currentIndex.size - baselineIndex.size,
      baselineVulnerable: Array.from(baselineIndex.values()).filter((item) => isVulnerable(item.algorithm)).length,
      currentVulnerable: Array.from(currentIndex.values()).filter((item) => isVulnerable(item.algorithm)).length,
    }

    const makeEvent = (
      key: string,
      item: Item,
      driftClass: DriftClass,
      before: string | null,
      after: string | null,
      summary: string,
      why: string,
      action: string,
      evidence: string[],
    ): DriftEvent => {
      const asset = item.assetId ? assetById.get(item.assetId) : assetByName.get(item.assetLabel.toLowerCase())
      const explanation = driftClass === 'planned' ? plannedExplanation(item.assetId, item.algorithm) : null
      return {
        id: `${driftClass}:${key}`,
        driftClass,
        source: 'scan-comparison',
        summary,
        assetId: item.assetId,
        assetName: item.assetLabel,
        environment: asset?.environment || 'unspecified',
        owner: asset?.owner || 'Unassigned',
        algorithm: item.algorithm,
        before,
        after,
        severity: item.severity,
        detectedAt: item.at,
        why,
        recommendedAction: action,
        evidence,
        explainedBy: explanation ? `${explanation.name} (${explanation.status})` : null,
        href: item.assetId ? `/dashboard/migration-planner?asset=${encodeURIComponent(item.assetId)}` : '/dashboard/migration-planner',
      }
    }

    // Appeared since the baseline.
    for (const [key, item] of currentIndex) {
      const baselineItem = baselineIndex.get(key)
      if (baselineItem) {
        if (SEVERITY_RANK[item.severity] > SEVERITY_RANK[baselineItem.severity]) {
          events.push(makeEvent(
            key, item, 'regression', baselineItem.severity, item.severity,
            `${item.algorithm} severity worsened on ${item.assetLabel}`,
            'The same cryptography is now graded more severely than at the baseline scan, so its risk has increased.',
            'Review what changed on this asset and whether the new grading reflects a configuration change.',
            [`Baseline severity: ${baselineItem.severity}.`, `Current severity: ${item.severity}.`, `Baseline scan completed ${baseline.baselineAt}.`],
          ))
        }
        continue
      }
      const explanation = plannedExplanation(item.assetId, item.algorithm)
      const vulnerable = isVulnerable(item.algorithm)
      if (explanation) {
        events.push(makeEvent(
          key, item, 'planned', null, item.algorithm,
          `${item.algorithm} appeared on ${item.assetLabel}`,
          'A migration for this asset was active in the comparison window, so this change is expected rather than drift.',
          'Confirm the migration completed as designed, then re-baseline.',
          [`Explained by: ${explanation.name}.`, `Migration target: ${explanation.target || 'not recorded'}.`],
        ))
      } else {
        events.push(makeEvent(
          // An algorithm that APPEARED and carries no quantum risk is newly
          // DISCOVERED cryptography, not an improvement. Classifying it as one
          // counted every extra row a deeper scan found as risk reduction: on a
          // real tenant a 38-finding baseline against a 46-finding scan produced
          // 68 "improvements" - arithmetically impossible - and drove stability
          // to 0 while nothing had actually got worse.
          key, item, vulnerable ? 'regression' : 'coverage', null, item.algorithm,
          `${item.algorithm} appeared on ${item.assetLabel}`,
          vulnerable
            ? 'Quantum-vulnerable cryptography is present now that was not present at the baseline scan, and no approved migration explains it.'
            : 'Cryptography the baseline scan did not record has been observed. It carries no quantum risk, so this is a change in what the scan can see rather than a change in posture.',
          vulnerable
            ? 'Investigate the unplanned change and bring the asset back to the approved cryptographic stack.'
            : 'No action required. Confirm the deeper coverage was expected.',
          [`Not present in the baseline scan (${baseline.baselineAt}).`, `Observed in the current scan (${baseline.currentAt}).`, 'No migration job covers this asset in the window.'],
        ))
      }
    }

    // Disappeared since the baseline.
    for (const [key, item] of baselineIndex) {
      if (currentIndex.has(key)) continue
      const explanation = plannedExplanation(item.assetId, item.algorithm)
      // Symmetrically: only the disappearance of a QUANTUM-VULNERABLE item is a
      // risk improvement. A safe algorithm dropping out of the results is a
      // coverage change - usually narrower scan scope, never a security win.
      const wasVulnerable = isVulnerable(item.algorithm)
      const disappearClass: DriftClass = explanation ? 'planned' : wasVulnerable ? 'improvement' : 'coverage'
      events.push(makeEvent(
        key, item, disappearClass, item.algorithm, null,
        `${item.algorithm} no longer detected on ${item.assetLabel}`,
        explanation
          ? 'A migration for this asset completed in the window, and the cryptography it targeted is no longer detected.'
          : wasVulnerable
            ? 'Quantum-vulnerable cryptography present at the baseline scan is no longer detected. It may have been remediated, or the asset may simply not have been reachable in the latest scan.'
            : 'Cryptography present at the baseline scan is no longer detected. It carried no quantum risk, so this reflects scan coverage rather than a change in posture.',
        explanation
          ? 'Verify at runtime that the replacement is actually in use.'
          : wasVulnerable
            ? 'Confirm this was a deliberate remediation rather than reduced scan coverage.'
            : 'No action required. Check whether the latest scan covered the same surface.',
        [
          `Present in the baseline scan (${baseline.baselineAt}).`,
          `Absent from the current scan (${baseline.currentAt}).`,
          explanation ? `Explained by: ${explanation.name}.` : 'No migration job covers this asset in the window.',
        ],
      ))
    }
  }

  /* ---- Runtime downgrades: first-hand drift evidence ------------------ */
  const downgrades = inputs.runtimeEvents.filter((event) => Boolean(event.downgrade_detected))
  const downgradeIndex = new Map<string, { count: number; row: Row; first: number; last: number }>()
  for (const event of downgrades) {
    const asset = resolveAsset(event)
    const label = asset?.name || str(event.asset_name) || str(event.host) || 'Unattributed'
    const key = `${label.toLowerCase()}::${str(event.key_exchange_algorithm) || str(event.algorithm) || 'downgrade'}`
    const at = ms(event.observed_at || event.created_at)
    const existing = downgradeIndex.get(key)
    if (existing) {
      existing.count += 1
      existing.first = Math.min(existing.first, at)
      existing.last = Math.max(existing.last, at)
    } else {
      downgradeIndex.set(key, { count: 1, row: event, first: at, last: at })
    }
  }
  for (const [key, entry] of downgradeIndex) {
    const asset = resolveAsset(entry.row)
    const label = asset?.name || str(entry.row.asset_name) || str(entry.row.host) || 'Unattributed'
    const algorithm = str(entry.row.key_exchange_algorithm) || str(entry.row.algorithm) || 'classical key exchange'
    events.push({
      id: `runtime-downgrade:${key}`,
      driftClass: 'regression',
      source: 'runtime-downgrade',
      summary: `Negotiated downgrade to ${algorithm} on ${label}`,
      assetId: asset?.id ?? (str(entry.row.asset_id) || null),
      assetName: label,
      environment: asset?.environment || 'unspecified',
      owner: asset?.owner || 'Unassigned',
      algorithm,
      before: 'expected hybrid post-quantum key agreement',
      after: algorithm,
      severity: entry.count >= 10 ? 'high' : 'medium',
      detectedAt: entry.last ? new Date(entry.last).toISOString() : null,
      why: 'A hybrid post-quantum handshake was attempted and the session completed with classical cryptography. Runtime behaviour has drifted from the intended configuration.',
      recommendedAction: 'Investigate why the hybrid negotiation failed — usually an intermediary, a pinned cipher list or an out-of-date client.',
      evidence: [
        `${entry.count} downgrade event(s) recorded by the runtime collector.`,
        entry.first ? `First observed ${new Date(entry.first).toISOString()}.` : '',
        entry.last ? `Most recent ${new Date(entry.last).toISOString()}.` : '',
      ].filter(Boolean),
      explainedBy: null,
      href: '/dashboard/runtime-crypto-intel',
    })
  }

  /* ---- Ordering ------------------------------------------------------- */
  const CLASS_ORDER: Record<DriftClass, number> = { regression: 0, improvement: 1, planned: 2, coverage: 3, persistent: 4 }
  events.sort(
    (a, b) =>
      CLASS_ORDER[a.driftClass] - CLASS_ORDER[b.driftClass] ||
      SEVERITY_RANK[b.severity] - SEVERITY_RANK[a.severity] ||
      ms(b.detectedAt) - ms(a.detectedAt),
  )

  /* ---- Summary --------------------------------------------------------- */
  const counts: Record<DriftClass, number> = { regression: 0, improvement: 0, planned: 0, coverage: 0, persistent: 0 }
  for (const event of events) counts[event.driftClass] += 1
  const total = events.length
  const summary: DriftSummaryRow[] = (['regression', 'improvement', 'planned', 'coverage', 'persistent'] as DriftClass[]).map((key) => ({
    key,
    label: CLASS_LABEL[key],
    glyph: CLASS_GLYPH[key],
    count: counts[key],
    percent: pct(counts[key], total),
  }))

  /* ---- By asset --------------------------------------------------------- */
  const assetIndex = new Map<string, DriftEvent[]>()
  for (const event of events) {
    const key = event.assetName || 'Unattributed'
    assetIndex.set(key, [...(assetIndex.get(key) ?? []), event])
  }
  const byAsset: AssetDriftRow[] = Array.from(assetIndex.entries())
    .map(([assetName, rows]) => {
      const regressions = rows.filter((r) => r.driftClass === 'regression').length
      const improvements = rows.filter((r) => r.driftClass === 'improvement').length
      const worst = rows.reduce<Severity | null>(
        (acc, r) => (r.driftClass === 'regression' && (!acc || SEVERITY_RANK[r.severity] > SEVERITY_RANK[acc]) ? r.severity : acc),
        null,
      )
      return {
        assetId: rows[0].assetId,
        assetName,
        environment: rows[0].environment,
        regressions,
        improvements,
        planned: rows.filter((r) => r.driftClass === 'planned').length,
        netChange: improvements - regressions,
        worstSeverity: worst,
        href: rows[0].href,
      }
    })
    .sort((a, b) => b.regressions - a.regressions || a.netChange - b.netChange)

  /* ---- Stability score --------------------------------------------------- */
  const stability = buildStability(available, counts, postureDelta, downgradeIndex.size)

  const unplanned = counts.regression + counts.improvement

  return {
    generatedAt: new Date(now).toISOString(),
    hasBaseline: available,
    baseline,
    stability,
    kpis: {
      regressions: counts.regression,
      improvements: counts.improvement,
      planned: counts.planned,
      unplannedChanges: unplanned,
      assetsChanged: byAsset.length,
      runtimeDowngrades: downgradeIndex.size,
    },
    summary,
    events,
    byAsset,
    postureDelta,
    filters: {
      environments: Array.from(new Set(events.map((e) => e.environment).filter((v) => v && v !== 'unspecified'))).sort(),
      classes: (['regression', 'improvement', 'planned', 'coverage'] as DriftClass[]).filter((key) => counts[key] > 0),
    },
    evidence: {
      sources: ['PQC Scan Sessions', 'Graded Scan Findings', 'Runtime Crypto Telemetry', 'Migration Jobs'],
      note: available
        ? `Drift measured by comparing scan session ${baseline.baselineSessionId?.slice(0, 8)} (${baseline.baselineAt}) with ${baseline.currentSessionId?.slice(0, 8)} (${baseline.currentAt}). Changes explained by an approved migration are classified as planned and excluded from the unplanned-change count. Runtime downgrades come directly from collector telemetry.`
        : `${EVIDENCE_UNAVAILABLE}. ${baseline.note}`,
    },
  }
}

/* ================================================================== */
/* Stability                                                           */
/* ================================================================== */

/**
 * Stability is the share of the estate that did NOT change unexpectedly.
 *
 * It is `null` without a baseline. That matters: the natural default for a
 * "stability" metric is 100 — nothing has gone wrong! — which is precisely the
 * reading an unmonitored estate must never produce. Absence of measurement is
 * not evidence of stability.
 */
function buildStability(
  available: boolean,
  counts: Record<DriftClass, number>,
  postureDelta: DriftIntelligence['postureDelta'],
  runtimeDowngrades: number,
): StabilityScore {
  if (!available) {
    return {
      score: null,
      level: 'No Baseline',
      statement: 'Cryptographic stability cannot be measured without two completed scans.',
      basis: 'A stability score is only published once a baseline exists. An unmeasured estate is never reported as stable.',
    }
  }

  const population = Math.max(1, postureDelta ? Math.max(postureDelta.baselineFindings, postureDelta.currentFindings) : 1)
  const unplanned = counts.regression + counts.improvement
  // Regressions dominate: posture getting worse is the signal this page exists
  // for. An unexplained improvement is worth confirming but must not be
  // penalised as if it were damage, and coverage changes carry no weight at all
  // - a deeper scan is not instability.
  const regressionWeight = counts.regression * 2 + counts.improvement * 0.5
  const raw = 100 - Math.min(100, (regressionWeight / population) * 100) - Math.min(15, runtimeDowngrades * 5)
  const score = Math.max(0, Math.min(100, Math.round(raw)))

  const level = score >= 95 ? 'Stable' : score >= 80 ? 'Minor Drift' : score >= 55 ? 'Notable Drift' : 'Unstable'

  return {
    score,
    level,
    statement:
      unplanned === 0 && runtimeDowngrades === 0
        ? counts.coverage > 0
          ? `No change in cryptographic posture between the two most recent scans. ${counts.coverage} coverage change(s) reflect what each scan could see, not what changed.`
          : 'No unplanned cryptographic change was detected between the two most recent scans.'
        : `${counts.regression} regression(s) and ${counts.improvement} unplanned improvement(s) detected between the two most recent scans${runtimeDowngrades ? `, plus ${runtimeDowngrades} runtime downgrade(s)` : ''}.`,
    basis: `Share of the compared population (${population} item(s)) whose posture did not change unexpectedly. Regressions weigh double, unexplained improvements a half, and coverage changes nothing — cryptography appearing or disappearing that carries no quantum risk reflects scan scope, not instability. Runtime downgrades apply a bounded penalty of up to 15 points, and planned migration changes are excluded entirely.`,
  }
}

/* ================================================================== */
/* Filtering                                                           */
/* ================================================================== */

export interface DriftFilters {
  driftClass: 'all' | DriftClass
  environment: string
  severity: 'all' | Severity
  search: string
}

export const EMPTY_DRIFT_FILTERS: DriftFilters = {
  driftClass: 'all',
  environment: 'all',
  severity: 'all',
  search: '',
}

export function filterDriftEvents(rows: DriftEvent[], filters: DriftFilters): DriftEvent[] {
  const search = filters.search.trim().toLowerCase()
  return rows.filter((row) => {
    if (filters.driftClass !== 'all' && row.driftClass !== filters.driftClass) return false
    if (filters.environment !== 'all' && row.environment !== filters.environment) return false
    if (filters.severity !== 'all' && row.severity !== filters.severity) return false
    if (search) {
      const haystack = `${row.summary} ${row.assetName} ${row.algorithm} ${row.owner}`.toLowerCase()
      if (!haystack.includes(search)) return false
    }
    return true
  })
}

/** Guard used by both the UI and the check tool. */
export function isUnplanned(event: DriftEvent): boolean {
  return event.driftClass === 'regression' || event.driftClass === 'improvement'
}

