import { createHash } from 'node:crypto'

/**
 * Quantum Readiness score history (table: quantum_readiness_history,
 * schema: supabase/quantum-readiness-history.sql).
 *
 * The "Readiness vs Risk" trend must be the headline scores' OWN history. It
 * used to be a per-scan-session `100 - findings / assets` ratio — a different
 * metric that read "risk 100" beside a Quantum Risk Score of 57. This module
 * appends a row when the scored evidence changes and reads the series back, so
 * every point on the trend is a value the engine actually published.
 *
 * Failure is never fatal: a missing table (schema not applied) or a refused
 * write yields `available: false` with the reason, and the pages render that
 * state instead of borrowing a series.
 */

// eslint-disable-next-line @typescript-eslint/no-explicit-any
type Client = any

export const SCORE_HISTORY_ENGINE_VERSION = '2'
/** One row per tenant per window at most, so a running scan is not written once per refresh. */
const MIN_RECORD_INTERVAL_MS = 10 * 60 * 1000
/** After a "table missing" answer, wait this long before asking again. */
const MISSING_TABLE_RECHECK_MS = 10 * 60 * 1000
const HISTORY_POINTS = 24

export interface ScoreHistoryEntry {
  quantumReadiness: number
  quantumRisk: number
  hndlRisk: number
  pqcAdoption: number
  assetsAssessed: number
  cryptoComponents: number
  vulnerableComponents: number
  criticalFindings: number
  highFindings: number
}

export interface ScoreHistoryPoint {
  recordedAt: string
  label: string
  readiness: number
  risk: number
  hndlRisk: number
  pqcAdoption: number
  assetsAssessed: number
  cryptoComponents: number
}

export interface ScoreHistory {
  available: boolean
  /** Why history is unavailable, phrased for the reader. Null when available. */
  reason: string | null
  points: ScoreHistoryPoint[]
}

const lastRecorded = new Map<string, { at: number; fingerprint: string }>()
let tableMissingSince = 0

function isMissingTable(error: unknown): boolean {
  const e = error as { code?: string; message?: string } | null
  const text = `${e?.code || ''} ${e?.message || ''}`.toLowerCase()
  return text.includes('42p01') || text.includes('pgrst205') || text.includes('does not exist') || text.includes('could not find the table')
}

function isPermissionDenied(error: unknown): boolean {
  const e = error as { code?: string; message?: string } | null
  return `${e?.code || ''} ${e?.message || ''}`.toLowerCase().includes('42501')
}

export function scoreHistoryFingerprint(entry: ScoreHistoryEntry): string {
  return createHash('sha1').update(JSON.stringify([SCORE_HISTORY_ENGINE_VERSION, entry])).digest('hex')
}

/** Short axis label; adds the time when two points share a day. */
function labelPoints(rows: Array<Record<string, unknown>>): ScoreHistoryPoint[] {
  const dayOf = (iso: string) => new Date(iso).toLocaleDateString('en-US', { month: 'short', day: 'numeric', timeZone: 'UTC' })
  const dayCounts = new Map<string, number>()
  for (const row of rows) {
    const day = dayOf(String(row.recorded_at))
    dayCounts.set(day, (dayCounts.get(day) || 0) + 1)
  }
  return rows.map((row) => {
    const recordedAt = String(row.recorded_at)
    const day = dayOf(recordedAt)
    const time = new Date(recordedAt).toISOString().slice(11, 16)
    return {
      recordedAt,
      label: (dayCounts.get(day) || 0) > 1 ? `${day} ${time}` : day,
      readiness: Number(row.quantum_readiness) || 0,
      risk: Number(row.quantum_risk) || 0,
      hndlRisk: Number(row.hndl_risk) || 0,
      pqcAdoption: Number(row.pqc_adoption) || 0,
      assetsAssessed: Number(row.assets_assessed) || 0,
      cryptoComponents: Number(row.crypto_components) || 0,
    }
  })
}

const UNAVAILABLE_SCHEMA = 'Score history storage is not provisioned for this environment (supabase/quantum-readiness-history.sql).'
const UNAVAILABLE_ACCESS = 'Score history storage refused access — re-run supabase/data-api-grants.sql.'

/**
 * Reads the tenant's score history and, when `current` differs from the newest
 * stored row, appends it first. Returns the series oldest → newest.
 *
 * `current` is null when the tenant has no assessment evidence: nothing is
 * recorded, and an existing history is still returned.
 */
export async function syncScoreHistory(client: Client, userId: string, current: ScoreHistoryEntry | null): Promise<ScoreHistory> {
  if (tableMissingSince && Date.now() - tableMissingSince < MISSING_TABLE_RECHECK_MS) {
    return { available: false, reason: UNAVAILABLE_SCHEMA, points: [] }
  }

  let rows: Array<Record<string, unknown>> = []
  try {
    const { data, error } = await client
      .from('quantum_readiness_history')
      .select('recorded_at, quantum_readiness, quantum_risk, hndl_risk, pqc_adoption, assets_assessed, crypto_components, fingerprint')
      .eq('user_id', userId)
      .order('recorded_at', { ascending: false })
      .limit(HISTORY_POINTS)
    if (error) {
      if (isMissingTable(error)) {
        tableMissingSince = Date.now()
        return { available: false, reason: UNAVAILABLE_SCHEMA, points: [] }
      }
      return { available: false, reason: isPermissionDenied(error) ? UNAVAILABLE_ACCESS : 'Score history could not be read.', points: [] }
    }
    tableMissingSince = 0
    rows = (data as Array<Record<string, unknown>>) || []
  } catch {
    return { available: false, reason: 'Score history could not be read.', points: [] }
  }

  if (current) {
    const fingerprint = scoreHistoryFingerprint(current)
    const newest = rows[0]
    const memo = lastRecorded.get(userId)
    const unchanged = newest?.fingerprint === fingerprint || memo?.fingerprint === fingerprint
    const newestAt = newest ? Date.parse(String(newest.recorded_at)) || 0 : 0
    const lastAt = Math.max(newestAt, memo?.at || 0)
    if (!unchanged && Date.now() - lastAt >= MIN_RECORD_INTERVAL_MS) {
      const recordedAt = new Date().toISOString()
      lastRecorded.set(userId, { at: Date.now(), fingerprint })
      try {
        const { error } = await client.from('quantum_readiness_history').insert({
          user_id: userId,
          recorded_at: recordedAt,
          quantum_readiness: current.quantumReadiness,
          quantum_risk: current.quantumRisk,
          hndl_risk: current.hndlRisk,
          pqc_adoption: current.pqcAdoption,
          assets_assessed: current.assetsAssessed,
          crypto_components: current.cryptoComponents,
          vulnerable_components: current.vulnerableComponents,
          critical_findings: current.criticalFindings,
          high_findings: current.highFindings,
          fingerprint,
          engine_version: SCORE_HISTORY_ENGINE_VERSION,
        })
        if (!error) {
          rows.unshift({
            recorded_at: recordedAt,
            quantum_readiness: current.quantumReadiness,
            quantum_risk: current.quantumRisk,
            hndl_risk: current.hndlRisk,
            pqc_adoption: current.pqcAdoption,
            assets_assessed: current.assetsAssessed,
            crypto_components: current.cryptoComponents,
            fingerprint,
          })
          rows = rows.slice(0, HISTORY_POINTS)
        } else {
          console.warn('[quantum-readiness] score history not recorded:', error.message || error)
        }
      } catch (err) {
        console.warn('[quantum-readiness] score history not recorded:', err instanceof Error ? err.message : err)
      }
    }
    if (lastRecorded.size > 2000) lastRecorded.clear()
  }

  return { available: true, reason: null, points: labelPoints([...rows].reverse()) }
}
