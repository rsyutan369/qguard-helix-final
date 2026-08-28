/**
 * Data-freshness vocabulary shared by every dashboard shell.
 *
 * PURE module — no React, no Supabase — so the dashboards, the server and
 * `tools/dashboard-disclosure-check.ts` all reason about "how old is this
 * assessment?" with one implementation. Two panels answering that question
 * differently is how one page calls an estate current while another calls it
 * stale.
 *
 * The rule these encode: a timestamp alone is not disclosure. Every page in the
 * Quantum Readiness suite can be read as a claim about production RIGHT NOW —
 * an executive deck especially — so an assessment old enough to have drifted
 * must say so in words, where the reader will see it.
 */

/**
 * Hours beyond which an assessment no longer describes current production
 * posture. Three days: long enough that a deploy, a certificate rotation or a
 * newly discovered asset has plausibly landed since the measurement.
 */
export const STALE_AFTER_HOURS = 72

/**
 * Age of an assessment in hours.
 *
 * Returns `null` — never `0` — when there is no usable timestamp. Zero would
 * render as "just measured", turning an unknown into a reassuring answer, which
 * is the failure mode this whole module exists to prevent. A future timestamp
 * clamps to 0 rather than going negative.
 */
export function assessmentAgeHours(value: string | null | undefined): number | null {
  if (!value) return null
  const ms = new Date(value).getTime()
  if (!Number.isFinite(ms)) return null
  return Math.max(0, (Date.now() - ms) / 36e5)
}

/** Human age: "less than an hour", "5 hours", "3 days". */
export function describeAge(hours: number): string {
  if (!Number.isFinite(hours) || hours < 1) return 'less than an hour'
  if (hours < 48) {
    const whole = Math.round(hours)
    return `${whole} hour${whole === 1 ? '' : 's'}`
  }
  const days = Math.round(hours / 24)
  return `${days} day${days === 1 ? '' : 's'}`
}

/** True when the assessment is old enough that it may no longer be current. */
export function isStale(hours: number | null): boolean {
  return hours !== null && hours > STALE_AFTER_HOURS
}
