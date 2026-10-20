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
 *   Part B — `createPublicScanRouter` over real HTTP with the DEFAULT limits
 *     10 / 100 / 1,000 simultaneous visitors with distinct addresses: every
 *     visitor either completes or is told — in the stream, readably — why not
 *     and when to retry; nobody sees a bare transport error; the server keeps
 *     answering while the line is long. Plus single-flight across 100 visitors
 *     of one site, abandonment over a real socket, rate-limit and cache rules,
 *     and the JSON API's status codes.
 *
 * Exits non-zero on any failure.
 */

import express from 'express'
import { spawn } from 'node:child_process'
import type { AddressInfo } from 'node:net'
import type { Server } from 'node:http'
import { monitorEventLoopDelay } from 'node:perf_hooks'
import { PublicScanCoordinator, type CoordinatorOptions, type QueueEvent, type QueueTarget, type RunHooks } from '../src/api-server/public-scan-queue'
import { createPublicScanRouter, publicScanLimitsFromEnv } from '../src/api-server/public-scan'
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

interface StreamOutcome {
  status: number
  contentType: string
  events: Array<{ event: string; data: unknown }>
  outcome: 'complete' | 'refused' | 'error' | 'transport'
  refusalCode?: string
  refusalMessage?: string
  retryAfterSeconds?: number | null
  firstEventMs: number | null
  totalMs: number
  /** The socket-level cause when the connection itself failed. */
  transportError?: string
}

async function openStream(base: string, targetName: string, clientIp: string, options: { abortAfterMs?: number; accept?: string } = {}): Promise<StreamOutcome> {
  const started = Date.now()
  const controller = new AbortController()
  if (options.abortAfterMs !== undefined) setTimeout(() => controller.abort(), options.abortAfterMs)
  const events: StreamOutcome['events'] = []
  let firstEventMs: number | null = null
  try {
    const response = await fetch(`${base}/stream?target=${encodeURIComponent(targetName)}`, {
      headers: { accept: options.accept ?? 'text/event-stream', 'x-forwarded-for': clientIp },
      signal: controller.signal,
    })
    const contentType = response.headers.get('content-type') ?? ''
    if (!contentType.includes('text/event-stream')) {
      const body = (await response.json().catch(() => null)) as { error?: { code?: string; message?: string } } | null
      return { status: response.status, contentType, events, outcome: 'refused', refusalCode: body?.error?.code, refusalMessage: body?.error?.message, firstEventMs, totalMs: Date.now() - started }
    }
    const reader = response.body!.getReader()
    const decoder = new TextDecoder()
    let buffer = ''
    for (;;) {
      const { value, done } = await reader.read()
      if (done) break
      buffer += decoder.decode(value, { stream: true })
      let boundary: number
      while ((boundary = buffer.indexOf('\n\n')) >= 0) {
        const frame = buffer.slice(0, boundary)
        buffer = buffer.slice(boundary + 2)
        const name = /^event: (.+)$/m.exec(frame)?.[1]
        const data = /^data: (.+)$/m.exec(frame)?.[1]
        if (!name) continue
        firstEventMs ??= Date.now() - started
        events.push({ event: name, data: data ? JSON.parse(data) : null })
      }
    }
    const last = events.at(-1)
    const base0 = { status: response.status, contentType, events, firstEventMs, totalMs: Date.now() - started }
    if (last?.event === 'scan-complete') return { ...base0, outcome: 'complete' }
    if (last?.event === 'scan-refused') {
      const payload = last.data as { code: string; message: string; retryAfterSeconds: number | null }
      return { ...base0, outcome: 'refused', refusalCode: payload.code, refusalMessage: payload.message, retryAfterSeconds: payload.retryAfterSeconds }
    }
    if (last?.event === 'error') return { ...base0, outcome: 'error' }
    return { ...base0, outcome: 'transport' }
  } catch (error) {
    const cause = (error as { cause?: { code?: string; message?: string } })?.cause
    const transportError = String(cause?.code ?? cause?.message ?? (error as Error)?.message ?? error)
    return { status: 0, contentType: '', events, outcome: 'transport', firstEventMs, totalMs: Date.now() - started, transportError }
  }
}

async function serve(router: express.Router): Promise<{ base: string; server: Server }> {
  const app = express()
  app.use(express.json())
  app.use('/api/v1/public-scan', router)
  const server = await new Promise<Server>((resolve) => {
    const s = app.listen(0, '127.0.0.1', () => resolve(s))
  })
  server.keepAliveTimeout = 60_000
  const { port } = server.address() as AddressInfo
  return { base: `http://127.0.0.1:${port}/api/v1/public-scan`, server }
}

const ip = (index: number) => `203.0.${Math.floor(index / 250)}.${(index % 250) + 1}`

/** What the server process reports about itself after a load run. */
interface ServerReport {
  maxRunning: number
  scans: number
  eventLoopP99Ms: number
  eventLoopMaxMs: number
  rssMb: number
  cpuMs: number
}

/**
 * Child mode (`--serve`): the REAL router with default limits and synthetic
 * scans, alone in its process. `/__synthetic` is this harness's own endpoint —
 * the production router has nothing like it.
 */
async function serveChild(): Promise<void> {
  const scan = syntheticScan({ durationMs: Number(process.env.LOAD_CHECK_SCAN_MS ?? 400) })
  const lag = monitorEventLoopDelay({ resolution: 10 })
  lag.enable()
  const cpuAtStart = process.cpuUsage()
  const app = express()
  app.use(express.json())
  app.use('/api/v1/public-scan', createPublicScanRouter({ run: scan.run, log: false, initialScanEstimateMs: Number(process.env.LOAD_CHECK_SCAN_MS ?? 400) }))
  app.get('/__synthetic', (_req, res) => {
    const cpu = process.cpuUsage(cpuAtStart)
    const report: ServerReport = {
      maxRunning: scan.maxRunning,
      scans: [...scan.invocations.values()].reduce((sum, count) => sum + count, 0),
      eventLoopP99Ms: Math.round(lag.percentile(99) / 1e6),
      eventLoopMaxMs: Math.round(lag.max / 1e6),
      rssMb: Math.round(process.memoryUsage().rss / 1_048_576),
      cpuMs: Math.round((cpu.user + cpu.system) / 1000),
    }
    res.json(report)
  })
  const server = app.listen(0, '127.0.0.1', () => {
    process.stdout.write(`PORT ${(server.address() as AddressInfo).port}\n`)
  })
  server.keepAliveTimeout = 60_000
}

async function spawnServer({ scanMs }: { scanMs: number }): Promise<{ base: string; root: string; stop: () => Promise<void> }> {
  const child = spawn(process.execPath, [...process.execArgv, process.argv[1], '--serve'], {
    stdio: ['ignore', 'pipe', 'inherit'],
    env: { ...process.env, LOAD_CHECK_SCAN_MS: String(scanMs) },
  })
  const kill = () => child.kill()
  process.once('exit', kill)
  const port = await new Promise<number>((resolve, reject) => {
    let buffer = ''
    child.stdout!.on('data', (chunk: Buffer) => {
      buffer += chunk.toString()
      const match = /PORT (\d+)/.exec(buffer)
      if (match) resolve(Number(match[1]))
    })
    child.once('exit', (code) => reject(new Error(`load-check server exited early (${code})`)))
  })
  const root = `http://127.0.0.1:${port}`
  return {
    root,
    base: `${root}/api/v1/public-scan`,
    stop: async () => {
      process.removeListener('exit', kill)
      const exited = new Promise<void>((resolve) => child.once('exit', () => resolve()))
      child.kill()
      await exited
    },
  }
}

/** Polls /capabilities while the load runs — the server must keep answering. */
function responsivenessProbe(base: string) {
  const latencies: number[] = []
  let stop = false
  const done = (async () => {
    while (!stop) {
      const started = Date.now()
      try {
        await fetch(`${base}/capabilities`).then((r) => r.json())
        latencies.push(Date.now() - started)
      } catch {
        latencies.push(Number.POSITIVE_INFINITY)
      }
      await sleep(100)
    }
  })()
  return {
    async finish() {
      stop = true
      await done
      const sorted = [...latencies].sort((a, b) => a - b)
      return { samples: sorted.length, max: sorted.at(-1) ?? 0, p95: sorted[Math.floor(sorted.length * 0.95)] ?? 0 }
    },
  }
}

async function partB(): Promise<void> {
  const defaults = publicScanLimitsFromEnv()
  console.log(`\nPart B — HTTP/SSE layer, default limits: ${defaults.maxConcurrent} concurrent, line of ${defaults.maxQueue}, ${defaults.maxActivePerClient} per client while waiting, ${defaults.rateLimitPerMinute} new scans/min/client\n`)

  /* The server runs in a process of its own, as it does in production. With
     a thousand clients in the SAME process, the clients' own work starved the
     accept loop and the OS refused connections (ECONNREFUSED before any byte)
     — that measured the harness, not the server.

     10 and 100 visitors arrive in the same instant. 1,000 arrive across 2.5s:
     this Windows workstation refuses same-instant connects past roughly 230 to
     ANY listener — a bare `node:http` server with no application code drops
     768 of 1,000 same-instant connects, and none spread over 2s. 400 arrivals a
     second still overruns the line within ~1.3s. */
  for (const [visitors, spreadMs] of [[10, 0], [100, 0], [1_000, 2_500]] as const) {
    /* ~15s real scans compressed to 400ms; the shape of the line is what is
       under test, not the wall clock. */
    const { base, root, stop } = await spawnServer({ scanMs: 400 })
    const probe = responsivenessProbe(base)
    const results = await Promise.all(Array.from({ length: visitors }, async (_, i) => {
      if (spreadMs) await sleep(Math.floor((i * spreadMs) / visitors))
      return openStream(base, `site${i}.load.example.com`, ip(i))
    }))
    const probeResult = await probe.finish()
    const server = (await fetch(`${root}/__synthetic`).then((r) => r.json())) as ServerReport
    await stop()

    const completed = results.filter((r) => r.outcome === 'complete')
    const queued = results.filter((r) => r.events.some((e) => e.event === 'scan-queued'))
    const refused = results.filter((r) => r.outcome === 'refused')
    const transport = results.filter((r) => r.outcome === 'transport' || r.outcome === 'error')
    const expectedServed = Math.min(visitors, defaults.maxConcurrent + defaults.maxQueue)
    const label = `B ${String(visitors).padStart(4)} visitors${spreadMs ? ` over ${spreadMs / 1000}s` : ' at once'}`

    const causes = new Map<string, number>()
    for (const r of transport) {
      const cause = `${r.transportError ?? r.outcome} ${r.events.length ? `after ${r.events.length} events` : 'before any event'}`
      causes.set(cause, (causes.get(cause) ?? 0) + 1)
    }
    check(`${label}: nobody sees a bare transport error`, transport.length === 0, `${transport.length} transport/error${causes.size ? ` ${JSON.stringify(Object.fromEntries(causes))}` : ''}`)
    /* At least capacity + line complete. More can, when arrivals are still
       connecting as the first scans finish and free a place. */
    check(`${label}: every visitor completes or is refused — at least ${expectedServed} complete`, completed.length >= expectedServed && completed.length + refused.length === visitors, `${completed.length} complete, ${queued.length} waited in line`)
    check(`${label}: anyone refused is told the line is full, readably, with a retry time`, refused.every((r) => r.status === 200 && r.refusalCode === 'QUEUE_FULL' && Boolean(r.refusalMessage) && (r.retryAfterSeconds ?? 0) >= 5), `${refused.length} refused${refused[0] ? ` — "${refused[0].refusalMessage}" (retry ${refused[0].retryAfterSeconds}s)` : ''}`)
    check(`${label}: never more than ${defaults.maxConcurrent} scans at once`, server.maxRunning <= defaults.maxConcurrent && server.scans === completed.length, `peak ${server.maxRunning}, ${server.scans} scans for ${completed.length} reports`)
    const firstEvent = Math.max(...results.map((r) => r.firstEventMs ?? Number.POSITIVE_INFINITY))
    check(`${label}: every visitor hears from the server at once`, firstEvent < 2_000, `slowest first event ${firstEvent}ms`)
    const positionsOk = queued.every((r) => {
      const positions = r.events.filter((e) => e.event === 'scan-queued').map((e) => (e.data as { position: number }).position)
      return positions.every((p, i) => i === 0 || p < positions[i - 1]) && r.events.some((e) => e.event === 'scan-started')
    })
    check(`${label}: queue positions only move forward and end in scan-started`, positionsOk)
    check(`${label}: the server keeps answering under the load`, probeResult.max < 1_000, `${probeResult.samples} probes, p95 ${probeResult.p95}ms, max ${probeResult.max}ms; server event loop p99 ${server.eventLoopP99Ms}ms, max ${server.eventLoopMaxMs}ms, rss ${server.rssMb}MB`)
    const slowest = Math.max(...completed.map((r) => r.totalMs))
    console.log(`        ${visitors} visitors: last report after ${(slowest / 1000).toFixed(1)}s of synthetic 0.4s scans (${Math.ceil(completed.length / defaults.maxConcurrent)} rounds of ${defaults.maxConcurrent})`)
  }

  {
    const scan = syntheticScan({ durationMs: 400 })
    const { base, server } = await serve(createPublicScanRouter({ run: scan.run, log: false }))
    const results = await Promise.all(Array.from({ length: 100 }, (_, i) => openStream(base, 'popular.example.com', ip(i))))
    server.close()
    check('B single-flight: 100 visitors of one site → 1 scan', scan.invocations.get('popular.example.com:443') === 1, `${scan.invocations.get('popular.example.com:443')} run(s)`)
    check('B single-flight: all 100 receive the report', results.every((r) => r.outcome === 'complete'))
    check('B single-flight: 99 are told they share it', results.filter((r) => r.events.some((e) => e.event === 'scan-shared')).length === 99)
  }

  {
    const scan = syntheticScan({ durationMs: 3_000 })
    const { base, server } = await serve(createPublicScanRouter({ run: scan.run, log: false, maxConcurrent: 2, abandonGraceMs: 300 }))
    const leavers = [0, 1].map((i) => openStream(base, `leaver${i}.example.com`, ip(i), { abortAfterMs: 200 }))
    await Promise.all(leavers)
    await sleep(500)
    const arrival = await openStream(base, 'arrival.example.com', ip(9), { abortAfterMs: 300 })
    server.close()
    check('B abandonment: closing the tab stops the scan after the grace period', scan.aborted.filter((k) => k.startsWith('leaver')).length === 2, `${scan.aborted.length} aborted`)
    check('B abandonment: the next visitor starts at once instead of waiting', arrival.events.some((e) => e.event === 'scan-started') && !arrival.events.some((e) => e.event === 'scan-queued'))
  }

  {
    const scan = syntheticScan({ durationMs: 60 })
    const { base, server } = await serve(createPublicScanRouter({ run: scan.run, log: false, rateLimitPerMinute: 5 }))
    const invalid = await openStream(base, 'not a domain', ip(1))
    check('B refusals are readable in-stream (invalid target → 200 + scan-refused)', invalid.status === 200 && invalid.outcome === 'refused' && invalid.refusalCode === 'INVALID_TARGET', `${invalid.status} ${invalid.refusalCode}`)
    const plain = await openStream(base, 'not a domain', ip(1), { accept: 'application/json' })
    check('B a non-EventSource caller still gets the HTTP status', plain.status === 400 && plain.refusalCode === 'INVALID_TARGET', `${plain.status}`)

    const mine: StreamOutcome[] = []
    for (let i = 0; i < 6; i += 1) mine.push(await openStream(base, `rl${i}.example.com`, ip(2)))
    check('B rate limit: five new scans a minute complete', mine.slice(0, 5).every((r) => r.outcome === 'complete'))
    check('B rate limit: the sixth is told why and when, in-stream', mine[5].outcome === 'refused' && mine[5].refusalCode === 'RATE_LIMITED' && (mine[5].retryAfterSeconds ?? 0) > 0, `${mine[5].refusalCode} retry ${mine[5].retryAfterSeconds}s`)
    const cachedHit = await openStream(base, 'rl0.example.com', ip(2))
    check('B a recent result is served to a rate-limited visitor (cache before gates)', cachedHit.outcome === 'complete' && (cachedHit.events.at(-1)?.data as { report: { cached?: boolean } }).report.cached === true)

    /* A fresh visitor: three refusals and a cache hit first, then five new
       scans — all five must still be allowed, and only the sixth refused. */
    for (let i = 0; i < 3; i += 1) await openStream(base, 'not a domain', ip(4))
    const cachedForFresh = await openStream(base, 'rl1.example.com', ip(4))
    const fresh: StreamOutcome[] = []
    for (let i = 0; i < 5; i += 1) fresh.push(await openStream(base, `fresh${i}.example.com`, ip(4)))
    const sixth = await openStream(base, 'fresh5.example.com', ip(4))
    check('B refusals and cache hits are not charged to the visitor', cachedForFresh.outcome === 'complete' && fresh.every((r) => r.outcome === 'complete') && sixth.refusalCode === 'RATE_LIMITED', `${fresh.filter((r) => r.outcome === 'complete').length}/5 new scans allowed, sixth ${sixth.refusalCode ?? sixth.outcome}`)

    /* Joining a scan someone else started is free even when over the limit. */
    const slow = syntheticScan({ durationMs: 300 })
    const joinServer = await serve(createPublicScanRouter({ run: slow.run, log: false, rateLimitPerMinute: 1 }))
    await openStream(joinServer.base, 'spent.example.com', ip(5))
    const running = openStream(joinServer.base, 'running.example.com', ip(6))
    await sleep(40)
    const overLimitJoin = await openStream(joinServer.base, 'running.example.com', ip(5))
    await running
    joinServer.server.close()
    check('B a visitor over the limit may still watch a scan already running', overLimitJoin.outcome === 'complete' && overLimitJoin.events.some((e) => e.event === 'scan-shared'))
    server.close()
  }

  {
    const scan = syntheticScan({ durationMs: 300 })
    const { base, server } = await serve(createPublicScanRouter({ run: scan.run, log: false, maxConcurrent: 1 }))
    const holder = openStream(base, 'holder.example.com', ip(1))
    await sleep(40)
    const busy = await fetch(base, { method: 'POST', headers: { 'content-type': 'application/json', 'x-forwarded-for': ip(2) }, body: JSON.stringify({ target: 'other.example.com' }) })
    const busyBody = (await busy.json()) as { error?: { code?: string } }
    check('B JSON API at capacity: 503 + Retry-After + reason', busy.status === 503 && Number(busy.headers.get('retry-after')) >= 5 && busyBody.error?.code === 'SCANNER_BUSY', `${busy.status} ${busyBody.error?.code} retry-after ${busy.headers.get('retry-after')}`)
    const joined = await fetch(base, { method: 'POST', headers: { 'content-type': 'application/json', 'x-forwarded-for': ip(3) }, body: JSON.stringify({ target: 'holder.example.com' }) })
    check('B JSON API joins a running scan at capacity', joined.status === 200)
    await holder
    const caps = (await fetch(`${base}/capabilities`).then((r) => r.json())) as { data: { limits: Record<string, number>; load: Record<string, number> } }
    check('B capabilities disclose limits and live load (counts only)', caps.data.limits.concurrentScans === 1 && typeof caps.data.load.queued === 'number' && !JSON.stringify(caps.data.load).includes('example.com'))
    server.close()
  }
}

async function main(): Promise<void> {
  console.log('\nQGuard Helix — public scan load & fairness check')
  await partA()
  await partB()
  console.log(`\n${passed} passed, ${failed} failed\n`)
  process.exit(failed === 0 ? 0 : 1)
}

if (process.argv.includes('--serve')) void serveChild()
else void main()
