/**
 * Public scan — concurrency, fairness and truthful-refusal check.
 *
 *   npx tsx tools/public-scan-load-check.ts
 *
 * Offline and deterministic: the assessment is a SYNTHETIC scan (no network,
 * no third-party traffic), so a thousand visitors can be driven through the
 * real coordinator and the real HTTP/SSE layer in seconds. What it proves:
 *
 *   Part A — `PublicScanCoordinator` rules (public-scan-queue.ts)
 *     capacity is never exceeded; waiting visitors get positions and estimates
 *     that only move forward; a full line refuses with a reason; one scan per
 *     target however many visitors ask; late joiners are replayed the progress
 *     so far; a visitor who leaves releases their place (queued) or stops the
 *     scan (running) after the grace period, and a reconnect inside it keeps
 *     the place; the per-client share applies only when a scan must wait; a
 *     wedged scan times out and still frees its slot; a cancellation is never
 *     reported as a failure.
 *
 *   Part B — authenticated JSON/SSE, quota and error handling over real HTTP
 *   with isolated account dependencies and deterministic scanner fixtures.
 *
 * Exits non-zero on any failure.
 */

import express from 'express'
import type { AddressInfo } from 'node:net'
import type { Server } from 'node:http'
import { PublicScanCoordinator, type CoordinatorOptions, type QueueEvent, type QueueTarget, type RunHooks } from '../src/api-server/public-scan-queue'
import { createPublicScanRouter, type PublicScanRouterConfig } from '../src/api-server/public-scan'
import type { PublicScanAccount } from '../src/api-server/public-scan-account'
import { checkHostSyntax, canFollowRedirect } from '../src/lib/scanner/public-scan/safe-dns'
import { ScanCancelledError } from '../src/lib/scanner/public-scan/engines'
import type { PublicScanReport, PublicScanStage, PublicScanStageKey } from '../src/lib/scanner/public-scan/types'

let passed = 0
let failed = 0

function check(name: string, condition: boolean, detail = ''): void {
  if (condition) {
    passed += 1
    console.log(`  PASS  ${name}${detail ? ` — ${detail}` : ''}`)
  } else {
    failed += 1
    console.error(`  FAIL  ${name}${detail ? ` — ${detail}` : ''}`)
  }
}

const sleep = (ms: number) => new Promise<void>((resolve) => setTimeout(resolve, ms))

async function waitFor(predicate: () => boolean, timeoutMs = 5_000): Promise<boolean> {
  const deadline = Date.now() + timeoutMs
  while (Date.now() < deadline) {
    if (predicate()) return true
    await sleep(5)
  }
  return predicate()
}

// ─── Synthetic scan ───────────────────────────────────────────────────────────

const STAGE_KEYS: PublicScanStageKey[] = ['dns', 'tls', 'certificate', 'headers', 'quantum', 'report']

/** A clearly synthetic report: the coordinator and route only pass it through. */
function syntheticReport(target: QueueTarget): PublicScanReport {
  return {
    target: target.host,
    port: target.port,
    completedAt: new Date().toISOString(),
    synthetic: true,
  } as unknown as PublicScanReport
}

interface SyntheticScan {
  run: CoordinatorOptions['run']
  invocations: Map<string, number>
  aborted: string[]
  maxRunning: number
  running: number
}

/**
 * Emits the six stages across `durationMs`, then resolves. Honours the abort
 * signal like the real engines (rejects with ScanCancelledError) unless told
 * to ignore it — the coordinator must release the slot either way.
 */
function syntheticScan({ durationMs, ignoreSignal = false, hang = false }: { durationMs: number | ((target: QueueTarget) => number); ignoreSignal?: boolean; hang?: boolean }): SyntheticScan {
  const scan: SyntheticScan = { run: undefined as unknown as CoordinatorOptions['run'], invocations: new Map(), aborted: [], maxRunning: 0, running: 0 }
  scan.run = (target: QueueTarget, hooks: RunHooks) => {
    scan.invocations.set(target.key, (scan.invocations.get(target.key) ?? 0) + 1)
    scan.running += 1
    scan.maxRunning = Math.max(scan.maxRunning, scan.running)
    const total = typeof durationMs === 'function' ? durationMs(target) : durationMs
    return new Promise<PublicScanReport>((resolve, reject) => {
      const timers: ReturnType<typeof setTimeout>[] = []
      const settle = () => {
        scan.running -= 1
        for (const timer of timers) clearTimeout(timer)
      }
      hooks.signal.addEventListener('abort', () => {
        scan.aborted.push(target.key)
        if (ignoreSignal || hang) return
        settle()
        reject(new ScanCancelledError(target.host, target.port))
      }, { once: true })
      if (hang) return
      STAGE_KEYS.forEach((key, index) => {
        timers.push(setTimeout(() => {
          hooks.onStage({ key, label: key, description: key, state: 'complete' } as PublicScanStage)
          hooks.onObservation({ surface: 'tls', label: `${key} measured`, detail: '', status: 'info', severity: 'info', at: Date.now() })
        }, Math.round((total * (index + 1)) / (STAGE_KEYS.length + 1))))
      })
      timers.push(setTimeout(() => {
        settle()
        resolve(syntheticReport(target))
      }, total))
    })
  }
  return scan
}

const target = (host: string, port = 443): QueueTarget => ({ host, port, input: host, key: `${host}:${port}` })

function coordinator(scan: SyntheticScan, overrides: Partial<CoordinatorOptions> = {}): PublicScanCoordinator {
  return new PublicScanCoordinator({
    maxConcurrent: 3,
    maxQueue: 50,
    maxActivePerClient: 3,
    timeoutMs: 10_000,
    abandonGraceMs: 60,
    initialScanEstimateMs: 1_000,
    run: scan.run,
    isCancellation: (error) => error instanceof ScanCancelledError,
    ...overrides,
  })
}

/** A subscriber that records everything it is told. */
function recorder() {
  const events: QueueEvent[] = []
  return {
    events,
    send: (event: QueueEvent) => void events.push(event),
    has: (type: QueueEvent['type']) => events.some((event) => event.type === type),
    of: <T extends QueueEvent['type']>(type: T) => events.filter((event): event is Extract<QueueEvent, { type: T }> => event.type === type),
  }
}

// ─── Part A — the coordinator ─────────────────────────────────────────────────

async function partA(): Promise<void> {
  console.log('\nPart A — coordinator rules (synthetic scans)\n')

  {
    const scan = syntheticScan({ durationMs: 80 })
    const c = coordinator(scan)
    const visitors = Array.from({ length: 10 }, (_, index) => {
      const r = recorder()
      const admission = c.subscribe(target(`a${index}.example.com`), `client-${index}`, r.send)
      return { r, admission }
    })
    check('A1 every visitor admitted below the line limit', visitors.every((v) => v.admission.admitted))
    check('A1 capacity-many start at once', visitors.filter((v) => v.r.has('started')).length === 3)
    const firstPositions = visitors.map((v) => v.r.of('queued')[0]?.position).filter((p): p is number => typeof p === 'number')
    check('A1 the rest are told their place, 1..7', firstPositions.join(',') === '1,2,3,4,5,6,7', firstPositions.join(','))
    const firstEstimates = visitors.map((v) => v.r.of('queued')[0]?.estimatedWaitSeconds).filter((s): s is number => typeof s === 'number')
    check('A1 estimated waits never decrease down the line', firstEstimates.every((s, i) => i === 0 || s >= firstEstimates[i - 1]), firstEstimates.join(','))
    await waitFor(() => visitors.every((v) => v.r.has('complete')))
    check('A1 all ten complete', visitors.every((v) => v.r.has('complete')))
    check('A1 never more than capacity running', scan.maxRunning === 3, `peak ${scan.maxRunning}`)
    const monotonic = visitors.every((v) => {
      const positions = v.r.of('queued').map((e) => e.position)
      return positions.every((p, i) => i === 0 || p < positions[i - 1])
    })
    check('A1 a waiting visitor’s position only moves forward', monotonic)
    const orderOk = visitors.every((v) => {
      const types = v.r.events.map((e) => e.type)
      const started = types.indexOf('started')
      return started >= 0 && types.lastIndexOf('queued') < started && types.indexOf('stage') > started && types.at(-1) === 'complete'
    })
    check('A1 event order: queued* → started → stage… → complete', orderOk)
    const stats = c.stats()
    check('A1 counters settle', stats.running === 0 && stats.queued === 0 && stats.completed === 10, JSON.stringify(stats))
  }

  {
    const scan = syntheticScan({ durationMs: 200 })
    const c = coordinator(scan, { maxConcurrent: 1, maxQueue: 2 })
    const admissions = [0, 1, 2, 3].map((i) => c.subscribe(target(`q${i}.example.com`), `c${i}`, () => undefined))
    const refused = admissions[3]
    check('A2 a full line refuses the next visitor', refused.admitted === false && refused.code === 'QUEUE_FULL', refused.admitted === false ? refused.code : 'admitted')
    check('A2 the refusal says when to retry', refused.admitted === false && refused.retryAfterSeconds >= 5 && /full/.test(refused.message), refused.admitted === false ? `${refused.retryAfterSeconds}s` : '')
    for (const a of admissions) if (a.admitted) a.unsubscribe()
  }

  {
    const scan = syntheticScan({ durationMs: 140 })
    const c = coordinator(scan)
    const first = recorder()
    c.subscribe(target('shared.example.com'), 'origin', first.send)
    const crowd = Array.from({ length: 49 }, () => recorder())
    crowd.forEach((r, i) => c.subscribe(target('shared.example.com'), `viewer-${i}`, r.send))
    await sleep(75)
    const late = recorder()
    c.subscribe(target('shared.example.com'), 'late', late.send)
    const stagesAtJoin = first.of('stage').length
    await waitFor(() => [first, late, ...crowd].every((r) => r.has('complete')))
    check('A3 fifty visitors of one site → one scan', scan.invocations.get('shared.example.com:443') === 1, `${scan.invocations.get('shared.example.com:443')} run(s)`)
    check('A3 every viewer receives the report', [first, late, ...crowd].every((r) => r.of('complete').length === 1))
    check('A3 joiners are told they share it', crowd.every((r) => r.has('shared')) && late.of('shared')[0]?.viewers === 51, `late joiner sees ${late.of('shared')[0]?.viewers} viewers`)
    const lateStages = late.events.filter((e) => e.type === 'stage').length
    check('A3 a late joiner is replayed the stages so far, then the rest', stagesAtJoin > 0 && lateStages === STAGE_KEYS.length, `${stagesAtJoin} at join, ${lateStages} received`)
    check('A3 a late joiner is replayed the observations so far', late.of('observation').length === STAGE_KEYS.length)
  }

  {
    const scan = syntheticScan({ durationMs: 300 })
    const c = coordinator(scan, { maxConcurrent: 1 })
    c.subscribe(target('busy.example.com'), 'a', () => undefined)
    const leaving = c.subscribe(target('left.example.com'), 'b', () => undefined)
    const after = recorder()
    c.subscribe(target('after.example.com'), 'c', after.send)
    check('A4 setup: one running, two waiting', c.stats().queued === 2)
    if (leaving.admitted) leaving.unsubscribe()
    await sleep(30)
    check('A4 a waiting visitor keeps their place inside the grace period', c.stats().queued === 2)
    await waitFor(() => c.stats().queued === 1, 1_000)
    check('A4 …and gives it up after it', c.stats().queued === 1 && c.stats().abandoned === 1, JSON.stringify(c.stats()))
    check('A4 the visitor behind moves up', after.of('queued').at(-1)?.position === 1, `position ${after.of('queued').at(-1)?.position}`)
    await waitFor(() => after.has('complete'), 2_000)
    check('A4 a withdrawn scan never runs', !scan.invocations.has('left.example.com:443'))
  }

  {
    const scan = syntheticScan({ durationMs: 2_000 })
    const c = coordinator(scan, { maxConcurrent: 1 })
    const viewer = recorder()
    const running = c.subscribe(target('abandon.example.com'), 'a', viewer.send)
    const next = recorder()
    c.subscribe(target('next.example.com'), 'b', next.send)
    if (running.admitted) running.unsubscribe()
    await waitFor(() => next.has('started'), 1_000)
    check('A5 a scan nobody watches is stopped after the grace period', scan.aborted.includes('abandon.example.com:443'))
    check('A5 its slot goes to the next visitor at once', next.has('started'))
    check('A5 a cancellation is not counted or reported as a failure', c.stats().failed === 0 && !viewer.has('failed'), JSON.stringify(c.stats()))
  }

  {
    const scan = syntheticScan({ durationMs: 150 })
    const c = coordinator(scan, { abandonGraceMs: 80 })
    const first = c.subscribe(target('reload.example.com'), 'a', () => undefined)
    await sleep(20)
    if (first.admitted) first.unsubscribe()
    await sleep(30)
    const again = recorder()
    const second = c.subscribe(target('reload.example.com'), 'a', again.send)
    await waitFor(() => again.has('complete'), 1_000)
    check('A6 a reload inside the grace period resumes the same scan', second.admitted && second.created === false && again.has('complete'))
    check('A6 …without starting a second one or aborting the first', scan.invocations.get('reload.example.com:443') === 1 && scan.aborted.length === 0)
  }

  {
    const scan = syntheticScan({ durationMs: 300 })
    const c = coordinator(scan, { maxConcurrent: 1, maxActivePerClient: 2 })
    const idle = coordinator(syntheticScan({ durationMs: 50 }), { maxConcurrent: 6, maxActivePerClient: 2 })
    const office = [0, 1, 2, 3, 4].map((i) => idle.subscribe(target(`office${i}.example.com`), 'office-nat', () => undefined))
    check('A7 with slots free, one address is not held to its share', office.every((a) => a.admitted), `${office.filter((a) => a.admitted).length}/5 admitted`)
    c.subscribe(target('other.example.com'), 'someone', () => undefined)
    const mine = [0, 1, 2].map((i) => c.subscribe(target(`mine${i}.example.com`), 'heavy', () => undefined))
    check('A7 under load one address holds at most its share of the line', mine[0].admitted && mine[1].admitted && mine[2].admitted === false && mine[2].code === 'CLIENT_BUSY', mine[2].admitted === false ? mine[2].code : 'admitted')
    const join = c.subscribe(target('other.example.com'), 'heavy', () => undefined)
    check('A7 joining a scan already in progress is always free', join.admitted && join.created === false)
    for (const a of [...office, ...mine, join]) if (a.admitted) a.unsubscribe()
  }

  {
    const scan = syntheticScan({ durationMs: 0, hang: true })
    const c = coordinator(scan, { maxConcurrent: 1, timeoutMs: 80 })
    const viewer = recorder()
    c.subscribe(target('wedged.example.com'), 'a', viewer.send)
    const next = recorder()
    c.subscribe(target('after-wedge.example.com'), 'b', next.send)
    await waitFor(() => viewer.has('failed'), 1_000)
    check('A8 a wedged scan that ignores its signal times out', viewer.of('failed')[0]?.message.includes('time budget') === true, viewer.of('failed')[0]?.message)
    await waitFor(() => next.has('started'), 500)
    check('A8 …and still releases its slot', next.has('started') && c.stats().failed === 1)
  }

  {
    const scan = syntheticScan({ durationMs: 2_000, ignoreSignal: true })
    const c = coordinator(scan, { maxConcurrent: 1 })
    const running = c.subscribe(target('deaf.example.com'), 'a', () => undefined)
    const next = recorder()
    c.subscribe(target('after-deaf.example.com'), 'b', next.send)
    if (running.admitted) running.unsubscribe()
    await waitFor(() => next.has('started'), 1_000)
    check('A9 an abandoned scan that ignores its signal still frees the slot', next.has('started'))
  }

  {
    const c = coordinator(syntheticScan({ durationMs: 0 }), {
      maxConcurrent: 1,
      run: () => {
        throw new Error('engine exploded before returning')
      },
    })
    const viewer = recorder()
    c.subscribe(target('throws.example.com'), 'a', viewer.send)
    await waitFor(() => viewer.has('failed'), 500)
    check('A10 a scan that throws synchronously fails cleanly', viewer.of('failed')[0]?.message === 'engine exploded before returning')
    await sleep(10)
    check('A10 …and releases its slot', c.stats().running === 0, JSON.stringify(c.stats()))
  }

  {
    const scan = syntheticScan({ durationMs: 200 })
    const c = coordinator(scan, { maxConcurrent: 1 })
    c.subscribe(target('script.example.com'), 'a', () => undefined)
    const busy = c.subscribe(target('script2.example.com'), 'b', () => undefined, { allowQueue: false })
    check('A11 the JSON API never queues: busy is SCANNER_BUSY', busy.admitted === false && busy.code === 'SCANNER_BUSY')
    const join = c.subscribe(target('script.example.com'), 'b', () => undefined, { allowQueue: false })
    check('A11 …but it may join a running scan at capacity', join.admitted)
  }

  {
    const c = coordinator(syntheticScan({ durationMs: 60 }))
    const healthy = recorder()
    c.subscribe(target('fanout.example.com'), 'a', () => {
      throw new Error('dead socket')
    })
    c.subscribe(target('fanout.example.com'), 'b', healthy.send)
    await waitFor(() => healthy.has('complete'), 1_000)
    check('A12 one dead connection does not stop the others hearing the result', healthy.has('complete'))
  }
}

// ─── Part B — the HTTP/SSE layer ──────────────────────────────────────────────

function testAccounts() {
  const accounts = new Map<string, { used: number; pending?: string }>()
  let unavailable = false
  const authenticate: NonNullable<PublicScanRouterConfig['authenticate']> = async (token) => {
    const [id, state] = token.split('.')
    if (!id || state !== 'valid') return null
    return {
      id,
      async quota(operation, scanId) {
        if (unavailable) throw new Error('Private database details')
        const account = accounts.get(id) ?? { used: 0 }
        accounts.set(id, account)
        let status: Awaited<ReturnType<PublicScanAccount['quota']>>['status'] = 'ok'
        if (operation === 'reserve') {
          if (account.used === 3) status = 'exhausted'
          else if (account.pending) status = 'active'
          else account.pending = scanId
        } else if (scanId && account.pending === scanId) {
          if (operation === 'complete') account.used += 1
          delete account.pending
        }
        return { status, usage: { limit: 3, remaining: 3 - account.used, resetAt: '2099-01-01T00:00:00Z', inProgress: !!account.pending } }
      },
    }
  }
  return { authenticate, outage: () => { unavailable = true } }
}

async function serve(options: PublicScanRouterConfig): Promise<{ base: string; server: Server }> {
  const app = express()
  app.use('/api/v1/public-scan', createPublicScanRouter(options))
  const server = await new Promise<Server>((resolve) => {
    const listening = app.listen(0, '127.0.0.1', () => resolve(listening))
  })
  const { port } = server.address() as AddressInfo
  return { base: `http://127.0.0.1:${port}/api/v1/public-scan`, server }
}

async function partB(): Promise<void> {
  console.log('\nB — Authenticated HTTP and SSE')
  const accounts = testAccounts()
  const scan = syntheticScan({ durationMs: 150 })
  const options: PublicScanRouterConfig = {
    log: false,
    maxConcurrent: 2,
    maxQueue: 3,
    rateLimitPerMinute: 25,
    abandonGraceMs: 30,
    authenticate: accounts.authenticate,
    verifyTarget: async (host) => host === 'private.example.com'
      ? { ok: false, code: 'PRIVATE_TARGET', message: 'This hostname cannot be assessed publicly.' }
      : { ok: true },
    run: (target, hooks) => {
      if (target.host === 'failure.example.com') throw new Error('Internal scanner error')
      if (target.host === 'unreachable.example.com') {
        return Promise.resolve({ ...syntheticReport(target), unreachable: true })
      }
      return scan.run(target, hooks)
    },
  }
  const one = await serve(options)
  const two = await serve(options)

  function request(
    route: typeof one, path: string, id?: string,
    target?: string | Record<string, string>, init: RequestInit = {},
  ) {
    const headers = new Headers(init.headers)
    if (id) headers.set('authorization', `Bearer ${id}`)
    if (target !== undefined) headers.set('content-type', 'application/json')
    return fetch(route.base + path, {
      ...init, headers, method: target === undefined ? 'GET' : 'POST',
      body: target === undefined ? undefined : JSON.stringify(typeof target === 'string' ? { target } : target),
    })
  }

  const usage = async (route: typeof one, account: string) => (await (await request(route, '/usage', account)).json()).data
  const alice = 'alice.valid.browser1'
  const bob = 'bob.valid.browser'
  try {
    const denied = await request(one, '/stream', undefined, 'alpha.example.com')
    check('Anonymous scan is rejected before scanner execution', denied.status === 401 && scan.invocations.size === 0)
    check('Anonymous allowance is rejected', (await request(one, '/usage')).status === 401)
    check('The API rejects expired sessions', (await request(one, '', 'alice.expired.browser', 'alpha.example.com')).status === 401)
    check('Creation by GET is rejected', (await request(one, '/stream?target=alpha.example.com', alice)).status === 405)
    const origin = await request(one, '/stream', alice, 'alpha.example.com', { headers: { origin: 'https://other.example' } })
    check('Unapproved browser origins are refused', origin.status === 403)

    check('The first session reads a full allowance', (await usage(one, alice)).remaining === 3)
    const started = await request(one, '/stream', alice, 'HTTPS://Alpha.example.com/a?discarded=1')
    const cancelledTwin = await request(two, '', 'alice.valid.other-device', 'race.example.com')
    check('A concurrent request on a second API process cannot start for the same account', cancelledTwin.status === 409)
    const bobScan = request(one, '', bob, 'beta.example.com')
    const frames = await started.text()
    check('Authenticated SSE delivers progress, a report and authoritative remaining usage',
      started.status === 200 && frames.includes('event: stage') && frames.includes('event: scan-complete') &&
      frames.includes('"remaining":2') && !frames.includes('discarded=1') &&
      started.headers.get('cache-control')?.includes('no-store') === true)
    const bobResult = await bobScan
    check('A different authenticated account can scan concurrently', bobResult.status === 200 && (await bobResult.json()).usage.remaining === 2)
    check('Reload and a second session see the same stored account allowance',
      (await usage(two, 'alice.valid.browser2')).remaining === 2)

    const cached = await request(one, '', alice, 'alpha.example.com')
    const cachedBody = await cached.json()
    check('A reused report does not execute again or spend quota', cached.status === 200 &&
      cachedBody.data.cached === true && cachedBody.usage.remaining === 2 && scan.invocations.get('alpha.example.com:443') === 1)

    for (const input of ['localhost', 'https://127.0.0.1', 'https://169.254.169.254', 'https://[::1]',
      'https://example.com:22', 'https://name:password@example.com', 'ftp://example.com', 'private.example.com']) {
      const response = await request(one, '/stream', alice, input)
      check(`Rejects restricted or invalid target: ${input}`, response.status === 400)
    }
    const oversized = await request(one, '', alice, 'a'.repeat(1_500))
    check('Oversized JSON is rejected before admission', oversized.status === 413)
    const extraFields = await request(one, '', alice, { target: 'alpha.example.com', accountId: 'bob' })
    check('Client parameters cannot select another account', extraFields.status === 400)
    const failedScan = await request(one, '', alice, 'failure.example.com')
    check('Engine errors are generic and do not spend quota',
      failedScan.status === 502 && !(await failedScan.text()).includes('Internal scanner error'))
    const unreachable = await request(one, '', alice, 'unreachable.example.com')
    check('Unreachable assessments explain the failure without spending quota',
      unreachable.ok && (await unreachable.json()).usage.remaining === 2)

    const cancellation = new AbortController()
    const abandoned = await request(one, '/stream', alice, 'abandoned.example.com', { signal: cancellation.signal })
    check('Authenticated cancellation test opened a stream', abandoned.ok)
    cancellation.abort()
    check('Closing the stream cancels abandoned work',
      await waitFor(() => scan.aborted.includes('abandoned.example.com:443'), 2_000))
    check('Cancellation returns the reservation without consuming a scan', (await usage(one, alice)).remaining === 2)
    for (const remaining of [1, 0]) {
      const response = await request(two, '', alice, `quota-${remaining}.example.com`)
      check(`Completing an uncached scan leaves ${remaining}/3`, response.ok && (await response.json()).usage.remaining === remaining)
    }
    const exhausted = await request(one, '/stream', 'alice.valid.other-device', 'alpha.example.com')
    check('A fourth request is rejected with 429, reset and Retry-After before cache lookup',
      exhausted.status === 429 && Number(exhausted.headers.get('retry-after')) > 0 &&
      (await exhausted.json()).usage.remaining === 0)
    check('Another account still has its own allowance', (await usage(two, bob)).remaining === 2)

    accounts.outage()
    const outage = await request(one, '', bob, 'no-database.example.com')
    check('A quota outage fails closed without leaking backend errors',
      outage.status === 503 && !(await outage.text()).includes('Private database details') &&
      !scan.invocations.has('no-database.example.com:443'))

    const rejected = await Promise.all(Array.from({ length: 8 }, () => request(two, '/usage')))
    const throttled = await request(two, '/usage')
    check('Repeated authentication failures are throttled', rejected.every((response) => response.status === 401) && throttled.status === 429)
    check('Literal and redirect policy rejects special-use address ranges, credentials and unsupported ports',
      !checkHostSyntax('0000:0000:0000:0000:0000:ffff:a9fe:a9fe').ok &&
      !checkHostSyntax('64:ff9b::a9fe:a9fe').ok &&
      !checkHostSyntax('168.63.129.16').ok &&
      !canFollowRedirect('https://user@example.com').ok &&
      !canFollowRedirect('https://example.com:2375').ok &&
      checkHostSyntax('2606:4700::1111').ok)
  } finally {
    for (const { server } of [one, two]) {
      server.closeAllConnections()
      server.close()
    }
  }
}

async function main(): Promise<void> {
  console.log('\nQGuard Helix — public scan load & fairness check')
  await partA()
  await partB()
  console.log(`\n${passed} passed, ${failed} failed\n`)
  process.exit(failed === 0 ? 0 : 1)
}

void main().catch((error) => { console.error(error); process.exitCode = 1 })
