/**
 * Scan-session payload shaping.
 *
 * `pqc_scan_sessions.metadata` is the scan's stored evidence record. It is read
 * back by scan history AND was selected by a dozen dashboard aggregations, so
 * its size is a platform-wide cost, not a scanner-local one.
 *
 * The buffered SSE event log used to be persisted verbatim. Measured across 32
 * real sessions (13.10MB of metadata), the event log alone was 8.24MB, and its
 * weight sat almost entirely in payloads the record ALREADY stores once:
 *
 *     finding        2685KB   also in metadata.results[].findings and in the
 *                             pqc_scan_results table
 *     result         1659KB   also in metadata.results
 *     module          613KB   module descriptor; only .name is ever rendered
 *     moduleStates    520KB   also in metadata.moduleStates
 *     metrics         414KB   aggregate counters, also in metadata.summary
 *     modules         264KB   static module catalog, identical every scan
 *     moduleCatalog   260KB   static module catalog, identical every scan
 *     summary         172KB   also in metadata.summary
 *
 * Scan history renders only the event envelope — timestamp, type, status,
 * message, phase, severity, moduleName / module.name — and restores findings
 * from `metadata.results`, never from the event log. So the copies above are
 * dead weight in the row and pure cost on every read.
 *
 * This module keeps the audit trail complete in the dimension that matters —
 * every event, in order, with its envelope intact — while removing duplicates
 * the same record still holds exactly once.
 */

/**
 * Event keys dropped at persistence time because the session's metadata (or the
 * relational scan tables) already store them. Removing them loses no evidence;
 * it removes copies. The live SSE stream is untouched, so the UI still receives
 * every payload in full while a scan runs.
 */
export const TELEMETRY_DUPLICATED_KEYS = [
  // Findings and per-target results: also metadata.results + pqc_scan_results.
  'finding',
  'findings',
  'result',
  'results',
  // Module state and the static catalog: also metadata.moduleStates.
  'moduleStates',
  'moduleLedger',
  'modules',
  'moduleCatalog',
  // Scan-level rollups: also metadata.summary / metadata.enterpriseScanner2.
  'summary',
  'metrics',
  'enterpriseScanner2',
  // Link sets: also stored as their own metadata keys.
  'linkedAssetIds',
  'linkedCbomIds',
  'linkedExposureIds',
  // Guards against an event ever nesting the log inside itself.
  'telemetry',
] as const

/**
 * Hard ceiling on stored events, so row size is bounded by the cap rather than
 * by how many targets a scan happened to sweep.
 */
export const MAX_STORED_TELEMETRY_EVENTS = 1000

/**
 * `module` is not dropped outright: scan history renders `event.module?.name`.
 * It is reduced to the identity fields the UI reads, so a ~19KB-per-row
 * descriptor becomes a few bytes without breaking the module label.
 */
function slimModule(value: unknown): unknown {
  if (!value || typeof value !== 'object' || Array.isArray(value)) return value
  const source = value as Record<string, unknown>
  const slim: Record<string, unknown> = {}
  for (const key of ['id', 'name', 'status']) {
    if (source[key] !== undefined) slim[key] = source[key]
  }
  return Object.keys(slim).length > 0 ? slim : value
}

/**
 * Shapes the in-memory telemetry buffer into the form written to
 * `pqc_scan_sessions.metadata.telemetry`.
 *
 * When the ceiling trims events, the gap is represented by an explicit
 * `telemetry-truncated` marker carrying the dropped and total counts — a
 * partial log is never presented as a complete one.
 */
export function persistableTelemetry(telemetry: Record<string, unknown>[]): Record<string, unknown>[] {
  const duplicated = new Set<string>(TELEMETRY_DUPLICATED_KEYS)

  const lean = (telemetry || []).map((event) => {
    const slim: Record<string, unknown> = {}
    for (const [key, value] of Object.entries(event || {})) {
      if (duplicated.has(key)) continue
      slim[key] = key === 'module' ? slimModule(value) : value
    }
    return slim
  })

  if (lean.length <= MAX_STORED_TELEMETRY_EVENTS) return lean

  // Keep the opening events (target validation, module start-up) and the tail
  // (findings, scoring, completion); the middle is repetitive per-target
  // progress chatter.
  const head = Math.floor(MAX_STORED_TELEMETRY_EVENTS / 4)
  const tail = MAX_STORED_TELEMETRY_EVENTS - head
  const dropped = lean.length - MAX_STORED_TELEMETRY_EVENTS

  return [
    ...lean.slice(0, head),
    {
      timestamp: new Date().toISOString(),
      type: 'telemetry-truncated',
      status: 'info',
      message: `${dropped} intermediate progress event(s) omitted from stored history; the full stream was delivered live.`,
      droppedEvents: dropped,
      totalEvents: lean.length,
    },
    ...lean.slice(-tail),
  ]
}
