/**
 * Real Time Scanning — live end-to-end check against the running dev server.
 *
 *   npx tsx tools/live-scan-live-check.ts [email] [origin]
 *
 * Signs a QA user in (admin magic link), then through the REAL API:
 *  1. starts a live scan of two badssl.com fixtures,
 *  2. streams SSE, disconnects part-way and resumes with `after=<seq>`,
 *  3. exercises pause / resume,
 *  4. verifies the stream reconstructs exactly the server snapshot,
 *  5. verifies a second tenant gets 404 for the run (isolation),
 *  6. verifies the run persisted as a PQC Scanner session carrying the event log,
 *     and that counters derived from the stored log equal the live ones,
 *  7. reopens the completed run without rerunning it,
 *  8. deletes the scan history it created (the scanner's own delete route).
 *
 * Never run in parallel with another magic-link probe for the same user.
 */

import 'dotenv/config'
import { createClient } from '@supabase/supabase-js'
import { applyEvents, emptyGraph, summarize } from '@/lib/live-scan/graph-reducer'
import type { LiveEvent } from '@/lib/live-scan/types'

const EMAIL = process.argv[2] || 'zachmatthew369@gmail.com'
const OTHER_EMAIL = 'teslagreat101@gmail.com'
const ORIGIN = process.argv[3] || 'http://localhost:3000'
const SUPA = process.env.VITE_SUPABASE_URL!
const BASE = `${ORIGIN}/api/v1/scanner/live`

let passed = 0
let failed = 0
function check(name: string, ok: unknown, detail?: unknown) {
  if (ok) { passed += 1; console.log(`  PASS  ${name}`) } else { failed += 1; console.log(`  FAIL  ${name}${detail !== undefined ? ` — ${JSON.stringify(detail).slice(0, 300)}` : ''}`) }
}

async function signIn(email: string): Promise<string> {
  const admin = createClient(SUPA, process.env.SUPABASE_SERVICE_ROLE_KEY!, { auth: { persistSession: false, autoRefreshToken: false } })
  const { data: link, error } = await admin.auth.admin.generateLink({ type: 'magiclink', email })
  if (error) throw error
  const anon = createClient(SUPA, process.env.VITE_SUPABASE_ANON_KEY!, { auth: { persistSession: false, autoRefreshToken: false } })
  const { data: otp, error: otpError } = await anon.auth.verifyOtp({ token_hash: (link as any).properties.hashed_token, type: 'magiclink' })
  if (otpError || !otp.session) throw otpError || new Error('no session')
  return otp.session.access_token
}

async function api(token: string, path: string, init?: RequestInit) {
  const response = await fetch(`${BASE}${path}`, { ...init, headers: { Authorization: `Bearer ${token}`, 'Content-Type': 'application/json', ...(init?.headers ?? {}) } })
  const text = await response.text()
  let body: any = null
  try { body = JSON.parse(text) } catch { body = text }
  return { status: response.status, body }
}

/** Read SSE until `stopAfter` events, `end`, or timeout. Returns events + whether `end` arrived. */
async function stream(token: string, runId: string, after: number, stopAfter: number, timeoutMs: number) {
  const controller = new AbortController()
  const timer = setTimeout(() => controller.abort(), timeoutMs)
  const events: LiveEvent[] = []
  let ended = false
  let heartbeats = 0
  try {
    const response = await fetch(`${BASE}/runs/${runId}/stream?after=${after}`, { headers: { Authorization: `Bearer ${token}`, Accept: 'text/event-stream' }, signal: controller.signal })
    const reader = response.body!.getReader()
    const decoder = new TextDecoder()
    let buffer = ''
    outer: for (;;) {
      const { value, done } = await reader.read()
      if (done) break
      buffer += decoder.decode(value, { stream: true })
      let index = buffer.indexOf('\n\n')
      while (index !== -1) {
        const frame = buffer.slice(0, index)
        buffer = buffer.slice(index + 2)
        const name = /^event: (.+)$/m.exec(frame)?.[1]
        const data = /^data: (.+)$/m.exec(frame)?.[1]
        if (name === 'live' && data) events.push(JSON.parse(data))
        if (name === 'heartbeat') heartbeats += 1
        if (name === 'end') { ended = true; break outer }
        if (events.length >= stopAfter) break outer
        index = buffer.indexOf('\n\n')
      }
    }
    controller.abort()
  } catch {
    // abort / timeout
  } finally {
    clearTimeout(timer)
  }
  return { events, ended, heartbeats }
}

;(async () => {
  console.log(`[live-scan e2e] ${EMAIL} @ ${ORIGIN}`)
  const token = await signIn(EMAIL)

  const unauth = await fetch(`${BASE}/runs`)
  check('unauthenticated request is rejected (401)', unauth.status === 401, unauth.status)

  const noAck = await api(token, '/runs', { method: 'POST', body: JSON.stringify({ targets: ['sha256.badssl.com'] }) })
  check('scan without authorization acknowledgement is refused (403)', noAck.status === 403, noAck.status)
  const privateTarget = await api(token, '/runs', { method: 'POST', body: JSON.stringify({ targets: ['127.0.0.1'], authorized: true }) })
  check('private / loopback target is refused (400)', privateTarget.status === 400, privateTarget.body)
  const internalName = await api(token, '/runs', { method: 'POST', body: JSON.stringify({ targets: ['intranet.local'], authorized: true }) })
  check('internal hostname is refused (400)', internalName.status === 400, internalName.body)

  const started = await api(token, '/runs', {
    method: 'POST',
    body: JSON.stringify({ name: 'E2E live-scan check', targets: ['sha256.badssl.com', 'expired.badssl.com', 'rsa2048.badssl.com'], authorized: true, concurrency: 1, targetTimeoutSec: 30 }),
  })
  check('scan accepted (202)', started.status === 202, started.body)
  const runId: string = started.body?.run?.id
  if (!runId) { console.log(`\n${passed} passed, ${failed} failed`); process.exit(1) }

  // Part 1: read some events, then drop the connection.
  const first = await stream(token, runId, 0, 25, 60_000)
  check('first stream delivered events in strictly increasing seq', first.events.length > 0 && first.events.every((event, i) => i === 0 || event.seq === first.events[i - 1].seq + 1), first.events.map((e) => e.seq))
  check('first event is the run creation / start', first.events[0]?.seq === 1)

  // Pause while running, verify state, resume.
  const paused = await api(token, `/runs/${runId}/pause`, { method: 'POST', body: '{}' })
  check('pause accepted and status is paused', paused.status === 200 && paused.body.run.status === 'paused', paused.body?.run?.status)
  const pausedSnap = await api(token, `/runs/${runId}`)
  check('snapshot reports paused', pausedSnap.body.run.status === 'paused')
  const resumed = await api(token, `/runs/${runId}/resume`, { method: 'POST', body: '{}' })
  check('resume accepted and status is running', resumed.status === 200 && resumed.body.run.status === 'running', resumed.body?.run?.status)

  // Isolation: another tenant cannot see or control the run.
  const otherToken = await signIn(OTHER_EMAIL)
  const foreign = await api(otherToken, `/runs/${runId}`)
  check('another tenant gets 404 for this run', foreign.status === 404, foreign.status)
  const foreignCancel = await api(otherToken, `/runs/${runId}/cancel`, { method: 'POST', body: '{}' })
  check('another tenant cannot cancel this run (404)', foreignCancel.status === 404, foreignCancel.status)

  // Part 2: resume the stream from the last seq we applied, to the end.
  const lastSeq = first.events[first.events.length - 1].seq
  const second = await stream(token, runId, lastSeq, Number.POSITIVE_INFINITY, 420_000)
  check('resumed stream continues exactly after the last applied seq', second.events[0]?.seq === lastSeq + 1, second.events[0]?.seq)
  check('stream closed with an end frame after the terminal event', second.ended)
  const all = [...first.events, ...second.events]
  const live = applyEvents(emptyGraph(), all)
  check('no gaps across reconnect (applied === lastSeq)', live.applied === live.lastSeq, { applied: live.applied, lastSeq: live.lastSeq })
  check('run reached a terminal status', ['completed', 'failed', 'cancelled'].includes(live.meta?.status ?? ''), live.meta?.status)

  const snap = await api(token, `/runs/${runId}`)
  const fromSnapshot = applyEvents(emptyGraph(), snap.body.events)
  check('streamed graph == snapshot graph (nodes)', Object.keys(live.nodes).length === Object.keys(fromSnapshot.nodes).length, [Object.keys(live.nodes).length, Object.keys(fromSnapshot.nodes).length])
  check('streamed graph == snapshot graph (edges, findings)', Object.keys(live.edges).length === Object.keys(fromSnapshot.edges).length && Object.keys(live.findings).length === Object.keys(fromSnapshot.findings).length)
  check('server summary == client-derived summary', JSON.stringify(snap.body.summary) === JSON.stringify(summarize(fromSnapshot)))
  const s = summarize(fromSnapshot)
  console.log(`    summary: ${JSON.stringify({ assets: s.assetsDiscovered, endpoints: s.endpointsInspected, certs: s.certificatesAnalyzed, chainsValidated: s.chainsValidated, chainsFailed: s.chainsFailed, algorithms: s.algorithmsObserved, exposed: s.quantumExposedAssets, findings: s.findingsTotal })}`)
  check('three assets discovered', s.assetsDiscovered === 3, s.assetsDiscovered)
  check('one valid chain (sha256) and the expired one not validated', s.chainsValidated >= 1 && fromSnapshot.nodes['endpoint:expired.badssl.com:443']?.data.chainTrusted !== true)
  check('expired certificate finding present', Object.values(fromSnapshot.findings).some((f) => f.type === 'CERTIFICATE_EXPIRED'))
  check('every finding carries evidence', Object.values(fromSnapshot.findings).every((f) => f.evidenceIds.length && f.evidenceIds.every((id) => fromSnapshot.evidence[id])))

  // Persistence: the PQC Scanner session row carries the log.
  const sessionId: string | null = snap.body.run.sessionId
  check('run linked to a database PQC scanner session', Boolean(sessionId) && snap.body.run.persistence === 'database', snap.body.run.persistence)
  const admin = createClient(SUPA, process.env.SUPABASE_SERVICE_ROLE_KEY!, { auth: { persistSession: false } })
  const { data: row } = await admin.from('pqc_scan_sessions').select('id, status, findings_count, metadata').eq('id', sessionId!).maybeSingle()
  const stored = (row?.metadata as any)?.liveScan
  check('stored session has the full event log', stored && stored.events.length === snap.body.events.length, [stored?.events?.length, snap.body.events.length])
  check('stored status matches live status', row?.status === snap.body.run.status, [row?.status, snap.body.run.status])
  const storedGraph = applyEvents(emptyGraph(), stored?.events ?? [])
  check('counters from stored record == live counters', JSON.stringify(summarize(storedGraph)) === JSON.stringify(summarize(fromSnapshot)))
  check('engine results persisted for downstream modules (assets/CBOM)', Array.isArray((row?.metadata as any)?.results) && (row?.metadata as any).results.length === 3 && ((row?.metadata as any).linkedAssetIds ?? []).length === 3)

  // Reopen by session id without rerunning.
  const reopened = await api(token, `/runs/${sessionId}`)
  check('completed run reopens by session id with identical events', reopened.status === 200 && reopened.body.events.length === snap.body.events.length)
  const replay = await stream(token, sessionId!, 0, Number.POSITIVE_INFINITY, 30_000)
  check('stream of a finished run replays then ends (no rescan)', replay.ended && replay.events.length === snap.body.events.length)
  const history = await api(token, '/runs')
  check('run listed in scan history', (history.body.runs ?? []).some((item: any) => item.id === sessionId || item.sessionId === sessionId))
  const controlAfter = await api(token, `/runs/${runId}/pause`, { method: 'POST', body: '{}' })
  check('finished run cannot be paused (409)', controlAfter.status === 409, controlAfter.status)

  // Export endpoints.
  const csv = await fetch(`${BASE}/runs/${runId}/export?format=csv`, { headers: { Authorization: `Bearer ${token}` } })
  const csvText = await csv.text()
  check('CSV export has a header + one row per finding', csvText.split('\n').length === Object.keys(fromSnapshot.findings).length + 1)

  // Cleanup through the scanner's own delete route.
  const del = await fetch(`${ORIGIN}/api/v1/scanner/history/${sessionId}`, { method: 'DELETE', headers: { Authorization: `Bearer ${token}` } })
  check('created scan history deleted', del.ok, del.status)

  console.log(`\n${passed} passed, ${failed} failed`)
  process.exit(failed ? 1 : 0)
})().catch((error) => { console.error(error); process.exit(1) })
