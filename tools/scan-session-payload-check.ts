/**
 * Scan-session stored payload — size discipline and evidence completeness.
 *
 *   npx tsx tools/scan-session-payload-check.ts
 *
 * Offline and deterministic: the inputs below are synthetic telemetry buffers,
 * so this runs without a network, a database or a live target.
 *
 * WHAT IT PINS, AND WHY
 * ---------------------
 * Dashboards were reporting empty because Postgres cancelled their queries:
 *
 *   Dashboard telemetry pqc_scan_sessions query skipped:
 *     canceling statement due to statement timeout
 *
 * The table held 32 rows. The cost was not row COUNT but row SIZE:
 * `metadata` averaged 419KB per session (worst 853KB) because the persisted
 * SSE event log re-stored the scan's large payloads — `results`, `moduleStates`,
 * `enterpriseScanner2` — which metadata ALSO stores as its own keys. Selecting
 * `metadata` moved 13.9MB per query; four concurrent took 20s, eight took 106s,
 * against an `authenticated` statement timeout of a few seconds.
 *
 * The positive controls check that duplication is gone and size is bounded.
 * The NEGATIVE controls are the important half: a "fix" that simply dropped
 * telemetry would satisfy every size assertion while destroying the audit
 * trail this platform is required to keep. So the event envelope — order,
 * timestamps, types, messages, progress, targets — must survive intact, and any
 * trimming must announce itself rather than pass a partial log off as whole.
 */

import {
  persistableTelemetry,
  MAX_STORED_TELEMETRY_EVENTS,
  TELEMETRY_DUPLICATED_KEYS,
} from '../src/lib/scanner/session-payload'

let failures = 0
function assert(condition: boolean, message: string) {
  if (condition) {
    console.log(`  ok   ${message}`)
  } else {
    failures++
    console.log(`  FAIL ${message}`)
  }
}

const kb = (value: unknown) => Buffer.byteLength(JSON.stringify(value ?? null)) / 1024

/** A finding payload of the size the real scanner emits. */
const heavyResults = [{
  target: 'example.test',
  findings: Array.from({ length: 120 }, (_, i) => ({
    id: `finding-${i}`,
    algorithm: 'RSA-2048',
    severity: 'high',
    description: 'x'.repeat(600),
    remediation: 'y'.repeat(400),
  })),
}]
const heavyModuleStates = Array.from({ length: 27 }, (_, i) => ({
  id: `module-${i}`, name: `Module ${i}`, status: 'Completed', detail: 'z'.repeat(300),
}))

/** Mirrors the scanner's buffer: envelopes, with big payloads on some events. */
function buildBuffer(eventCount: number) {
  const events: Record<string, unknown>[] = []
  for (let i = 0; i < eventCount; i++) {
    const event: Record<string, unknown> = {
      timestamp: new Date(Date.UTC(2026, 0, 1, 0, 0, i)).toISOString(),
      type: i === 0 ? 'scan-started' : 'target-progress',
      status: 'running',
      progress: Math.round((i / eventCount) * 100),
      message: `Event ${i}`,
      target: 'example.test',
    }
    // Mirrors the real emitter: per-finding events carry the whole finding,
    // per-target events carry the whole result, module events carry the full
    // descriptor and catalog, and the terminal event carries every rollup.
    if (i % 3 === 0) {
      if (i > 0) event.type = 'finding-detected'
      event.severity = 'high'
      event.finding = { id: `f-${i}`, algorithm: 'RSA-2048', description: 'x'.repeat(700) }
    }
    if (i % 7 === 0) {
      event.module = { id: `module-${i}`, name: `Module ${i}`, status: 'Completed', detail: 'z'.repeat(900) }
      event.moduleName = `Module ${i}`
      event.moduleCatalog = heavyModuleStates
      event.moduleStates = heavyModuleStates
    }
    if (i % 11 === 0) event.result = heavyResults[0]
    if (i === eventCount - 1) {
      event.type = 'scan-complete'
      event.results = heavyResults
      event.summary = { totalFindings: 120, riskScore: 71 }
      event.enterpriseScanner2 = { detail: 'q'.repeat(40000) }
      event.linkedCbomIds = Array.from({ length: 124 }, (_, n) => `cbom-${n}`)
    }
    events.push(event)
  }
  return events
}

console.log('\nPOSITIVE — duplicated payloads no longer inflate the stored row')
{
  const buffer = buildBuffer(384) // the observed real-world event count
  const stored = persistableTelemetry(buffer)
  const before = kb(buffer)
  const after = kb(stored)

  assert(after < before * 0.2, `stored log is far smaller than the raw buffer (${before.toFixed(0)}KB -> ${after.toFixed(0)}KB)`)
  assert(
    stored.every((event) => TELEMETRY_DUPLICATED_KEYS.every((key) => !(key in event))),
    'no stored event carries a payload that metadata already stores separately',
  )
  assert(after < 100, `a single-target scan's stored log stays under 100KB (${after.toFixed(0)}KB)`)
}

console.log('\nNEGATIVE — the audit trail is not what got thrown away')
{
  const buffer = buildBuffer(384)
  const stored = persistableTelemetry(buffer)

  assert(stored.length === buffer.length, `every event is retained (${stored.length}/${buffer.length})`)
  assert(
    stored.every((event, i) => event.timestamp === buffer[i].timestamp && event.type === buffer[i].type),
    'event order, timestamps and types are unchanged',
  )
  assert(
    stored.every((event, i) => event.message === buffer[i].message && event.progress === buffer[i].progress),
    'per-event message and progress survive',
  )
  assert(
    stored[stored.length - 1].type === 'scan-complete' && stored[0].type === 'scan-started',
    'terminal and opening events are still present',
  )
  assert(
    stored.every((event) => 'target' in event),
    'target attribution survives on every event',
  )

  // Scan history renders exactly these per-event fields (ScannerDashboard's
  // history restore): timestamp, type/status, message, phase, severity,
  // moduleName / module.name. Every one must still be there.
  const severityEvents = stored.filter((_, i) => i % 3 === 0)
  assert(severityEvents.every((event) => event.severity === 'high'), 'finding severity is still rendered per event')
  const moduleEvents = stored.filter((_, i) => i % 7 === 0)
  assert(
    moduleEvents.every((event) => typeof event.moduleName === 'string'),
    'moduleName survives for the history log label',
  )
  assert(
    moduleEvents.every((event) => (event.module as Record<string, unknown>)?.name !== undefined),
    'module.name survives — the UI falls back to it when moduleName is absent',
  )
  assert(
    moduleEvents.every((event) => (event.module as Record<string, unknown>)?.detail === undefined),
    'but the module descriptor is reduced to its identity, not kept whole',
  )
}

console.log('\nPOSITIVE — row size stays bounded no matter how large the scan')
{
  const huge = persistableTelemetry(buildBuffer(20000)) // a many-target sweep
  assert(
    huge.length <= MAX_STORED_TELEMETRY_EVENTS + 1,
    `a 20,000-event scan is capped (${huge.length} <= ${MAX_STORED_TELEMETRY_EVENTS} + marker)`,
  )
  assert(kb(huge) < 400, `even a capped worst case stays well under the old 853KB row (${kb(huge).toFixed(0)}KB)`)
}

console.log('\nNEGATIVE — trimming announces itself instead of faking a complete log')
{
  const huge = persistableTelemetry(buildBuffer(20000))
  const marker = huge.find((event) => event.type === 'telemetry-truncated')

  assert(Boolean(marker), 'a truncation marker is present when events are dropped')
  assert(
    Number(marker?.droppedEvents) === 20000 - MAX_STORED_TELEMETRY_EVENTS,
    `the marker states how many events were dropped (${marker?.droppedEvents})`,
  )
  assert(Number(marker?.totalEvents) === 20000, `the marker states the true total (${marker?.totalEvents})`)
  assert(
    huge[huge.length - 1].type === 'scan-complete',
    'the scan outcome is never the part that gets trimmed',
  )
  assert(
    persistableTelemetry(buildBuffer(50)).every((event) => event.type !== 'telemetry-truncated'),
    'no truncation marker is added when nothing was dropped',
  )
}

console.log('\nPOSITIVE — degenerate inputs do not throw')
{
  assert(persistableTelemetry([]).length === 0, 'an empty buffer yields an empty log')
  assert(
    persistableTelemetry([{}, { type: 'x' }]).length === 2,
    'events without payloads pass through unharmed',
  )
}

console.log(
  `\n${failures === 0 ? 'PASS' : 'FAIL'} — ${failures} failure(s).` +
    `\nstored single-scan log ${kb(persistableTelemetry(buildBuffer(384))).toFixed(0)}KB ` +
    `(raw buffer ${kb(buildBuffer(384)).toFixed(0)}KB) · cap ${MAX_STORED_TELEMETRY_EVENTS} events\n`,
)
process.exit(failures === 0 ? 0 : 1)
