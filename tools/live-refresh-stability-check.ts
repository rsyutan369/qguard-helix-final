/** Regression checks for interrupted JSON bodies, bounded transport and stable live snapshots.
 * Run: npx tsx tools/live-refresh-stability-check.ts
 * Uses only a loopback HTTP server and test fixtures; never reads or writes tenant data.
 */
import assert from 'node:assert/strict'
import { createServer } from 'node:http'
import { EventEmitter } from 'node:events'
import { createSingleFlightCache } from '../src/lib/single-flight-cache'
import { streamLiveSnapshot } from '../src/api-server/live-snapshot-stream'
import type { Request, Response } from 'express'

process.env.SUPABASE_MAX_SOCKETS = '2'
process.env.SUPABASE_MAX_ATTEMPTS = '3'
process.env.SUPABASE_REQUEST_TIMEOUT_MS = '3000'
const { supabaseFetch, supabaseTransportStats } = await import('../src/lib/supabase-fetch')
const sleep = (ms: number) => new Promise<void>(resolve => setTimeout(resolve, ms))
const attempts = new Map<string, number>()
let openBodies = 0, peakBodies = 0
const server = createServer((req, res) => {
  const path = req.url || '/'
  const attempt = (attempts.get(path) || 0) + 1
  attempts.set(path, attempt)
  if (path === '/stream') {
    res.writeHead(200, { 'Content-Type': 'text/event-stream' })
    res.write('event: connected\ndata: {}\n\n')
    return
  }
  if (path === '/empty') { res.writeHead(204); res.end(); return }
  res.writeHead(200, { 'Content-Type': 'application/json' })
  res.flushHeaders()
  if (path === '/post-cut' || path === '/get-cut' && attempt === 1) {
    res.write('{"ok":')
    setTimeout(() => res.destroy(), 30)
    return
  }
  if (path === '/slow') {
    openBodies++; peakBodies = Math.max(peakBodies, openBodies)
    res.on('close', () => { openBodies-- })
    res.write('{"ok":')
    setTimeout(() => res.end('true}'), 60)
    return
  }
  res.end('{"ok":true}')
})
await new Promise<void>(resolve => server.listen(0, '127.0.0.1', resolve))
const address = server.address()
assert(address && typeof address !== 'string')
const base = `http://127.0.0.1:${address.port}`
const pass = (message: string) => console.log(`PASS ${message}`)
try {
  const recovered = await supabaseFetch(`${base}/get-cut`)
  assert.deepEqual(await recovered.json(), { ok: true })
  assert.equal(attempts.get('/get-cut'), 2)
  assert.equal(recovered.url, `${base}/get-cut`)
  pass('A JSON body terminated after headers is retried safely for GET')

  await assert.rejects(supabaseFetch(`${base}/post-cut`, { method: 'POST', body: '{}' }))
  assert.equal(attempts.get('/post-cut'), 1)
  pass('An ambiguous interrupted POST is never replayed')

  await Promise.all(Array.from({ length: 9 }, async () => {
    const response = await supabaseFetch(`${base}/slow`)
    assert.deepEqual(await response.json(), { ok: true })
  }))
  assert(peakBodies <= 2, `Concurrent JSON bodies: ${peakBodies}`)
  assert.deepEqual(supabaseTransportStats(), { active: 0, queued: 0, limit: 2 })
  pass('The concurrency gate remains held through complete JSON bodies')

  const aborted = AbortSignal.abort(new Error('cancelled by caller'))
  await assert.rejects(supabaseFetch(`${base}/never-dispatched`, { signal: aborted }))
  assert.equal(attempts.get('/never-dispatched'), undefined)
  pass('Caller cancellation prevents dispatch and retries')

  const ctrl = new AbortController()
  const streamed = await supabaseFetch(`${base}/stream`, { signal: ctrl.signal })
  assert(streamed.body)
  const reader = streamed.body.getReader()
  assert((await reader.read()).value?.length)
  ctrl.abort()
  reader.releaseLock()
  assert.equal((await supabaseFetch(`${base}/empty`)).status, 204)
  pass('SSE remains streamed and empty responses remain readable')

  const cache = createSingleFlightCache<number>(15)
  let builds = 0
  const build = async () => { builds++; await sleep(50); return builds }
  const first = cache.get('tenant-a', build)
  await sleep(25)
  const second = cache.get('tenant-a', build)
  assert.equal(first, second)
  await first
  assert.equal(await cache.get('tenant-a', build), 1)
  assert.equal(builds, 1)
  assert.equal(await cache.get('tenant-b', build), 2)
  pass('Slow snapshot builds stay single-flight past TTL and are tenant scoped')

  const req = new EventEmitter()
  const writes: string[] = []
  const res = { status() { return this }, setHeader() {}, flushHeaders() {}, write(frame: string) { writes.push(frame) } }
  let inFlight = 0, peakBuilds = 0, emitted = 0
  streamLiveSnapshot(req as Request, res as unknown as Response, {
    event: 'sandbox-update', intervalMs: 15, heartbeatMs: 1000,
    build: async () => { inFlight++; peakBuilds = Math.max(peakBuilds, inFlight); await sleep(30); inFlight--; return { generatedAt: String(++emitted), simulations: [] } },
  })
  await sleep(115)
  req.emit('close')
  assert.equal(peakBuilds, 1)
  assert.equal(writes.filter(x => x.startsWith('event: sandbox-update\n')).length, 1)
  assert(writes.some(x => x.startsWith('event: sandbox-update-unchanged\n')))
  const closedCount = writes.length
  await sleep(50)
  assert.equal(writes.length, closedCount)
  pass('Unchanged SSE ticks do not resend snapshots, overlap builds or survive disconnect')
} finally {
  server.closeAllConnections()
  await new Promise<void>(resolve => server.close(() => resolve()))
}
