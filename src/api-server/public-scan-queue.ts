/**
 * Public scan coordinator — a fair waiting line, shared work, and no work for
 * nobody.
 *
 * ── What it replaced, measured ──────────────────────────────────────────────
 *
 * The route ran at most six assessments per process and refused everything
 * else with an instant 503. Measured against the dev server, all visitors
 * starting at once: 10 → 4 refused, 100 → 88 refused, 1,000 → 987 refused. The
 * browser's EventSource cannot read a non-200 body, so every one of them saw
 * "Connection to the assessment service was lost". Six visitors who closed
 * their tab after 1.5s kept their scans running to completion, and a new
 * visitor was refused while nobody was watching anything. A hundred visitors
 * scanning the same site each needed a slot of their own.
 *
 * ── What it does ────────────────────────────────────────────────────────────
 *
 *   QUEUE        Past the concurrency cap a visitor is ADMITTED to a bounded
 *                FIFO and told their position and an estimated wait, updated as
 *                the line moves. Refusal is reserved for a full line or a client
 *                already holding its share, and it says which.
 *   SHARE        One job per host:port. A visitor asking for a site that is
 *                already queued or running joins that job and receives its
 *                progress so far, then everything after — one scan, N viewers.
 *   STOP         A job nobody is watching is withdrawn from the line, or its
 *                scan is aborted, after a short grace period (a page reload or
 *                an EventSource reconnect must not cost a visitor their place).
 *
 * Pure: no Express, no sockets. The scan itself is an injected `run` function,
 * so `tools/public-scan-load-check.ts` drives the real coordinator with
 * synthetic scans and asserts every rule above deterministically.
 */

import type { PublicScanReport, PublicScanStage } from '@/lib/scanner/public-scan/types'

/** One measurement on its way to the live visualization. Opaque here. */
export type QueueObservation = Record<string, unknown>

export interface QueueTarget {
  host: string
  port: number
  input: string
  /** `host:port` — the identity two visitors share a job by. */
  key: string
}

/** Everything a subscriber can be told, in order. */
export type QueueEvent =
  | { type: 'queued'; position: number; queueLength: number; estimatedWaitSeconds: number; running: number; capacity: number }
  | { type: 'started' }
  | { type: 'shared'; viewers: number; state: 'queued' | 'running' }
  | { type: 'stage'; stage: PublicScanStage }
  | { type: 'observation'; observation: QueueObservation }
  | { type: 'complete'; report: PublicScanReport }
  | { type: 'failed'; message: string }

export type QueueRefusalCode = 'QUEUE_FULL' | 'CLIENT_BUSY' | 'SCANNER_BUSY'

export type Admission =
  | {
      admitted: true
      /** True when this request created the job (and so should be charged). */
      created: boolean
      unsubscribe: () => void
    }
  | {
      admitted: false
      code: QueueRefusalCode
      message: string
      retryAfterSeconds: number
    }

export interface RunHooks {
  onStage: (stage: PublicScanStage) => void
  onObservation: (observation: QueueObservation) => void
  signal: AbortSignal
}

export interface CoordinatorOptions {
  /** Scans allowed to run at once in this process. */
  maxConcurrent: number
  /** Jobs allowed to wait. Beyond this a visitor is refused with a reason. */
  maxQueue: number
  /**
   * Jobs one client may hold — queued or running, that it CREATED (joins are
   * free) — when a new one would have to wait. Not applied while a slot is free.
   */
  maxActivePerClient: number
  /** Backstop for a wedged scan; it is aborted and its viewers told so. */
  timeoutMs: number
  /** How long a job with no viewers survives before it is withdrawn or aborted. */
  abandonGraceMs: number
  /** Starting estimate of one scan's duration, refined from real completions. */
  initialScanEstimateMs: number
  run: (target: QueueTarget, hooks: RunHooks) => Promise<PublicScanReport>
  /** Called once per successful report — the route writes its cache here. */
  onReport?: (target: QueueTarget, report: PublicScanReport, durationMs: number) => void
  /** Called once per failed scan — never for a cancellation. */
  onFailure?: (target: QueueTarget, message: string, durationMs: number) => void
  /** True when an error means "cancelled", which is never reported as a failure. */
  isCancellation?: (error: unknown) => boolean
  now?: () => number
}

interface Subscriber {
  id: number
  send: (event: QueueEvent) => void
}

interface Job {
  target: QueueTarget
  state: 'queued' | 'running'
  subscribers: Map<number, Subscriber>
  createdBy: string
  controller: AbortController
  queuedAt: number
  startedAt: number | null
  /** Latest state of every stage, replayed to a visitor who joins late. */
  stages: Map<string, PublicScanStage>
  /** Recent observations, replayed to a visitor who joins late. Bounded. */
  observations: QueueObservation[]
  graceTimer: ReturnType<typeof setTimeout> | null
  /** Why the controller fired, so a timeout is reported and a desertion is not. */
  abortReason: 'abandoned' | 'timeout' | null
}

/** Observations replayed to a late joiner — enough to repaint the live hero. */
const REPLAY_OBSERVATIONS = 120

export interface QueueStats {
  capacity: number
  running: number
  queued: number
  queueCapacity: number
  viewers: number
  averageScanSeconds: number
  completed: number
  failed: number
  abandoned: number
}

export class PublicScanCoordinator {
  private readonly jobs = new Map<string, Job>()
  private readonly queue: Job[] = []
  private running = 0
  private nextSubscriberId = 1
  private averageScanMs: number
  private readonly counters = { completed: 0, failed: 0, abandoned: 0 }
  private readonly now: () => number

  constructor(private readonly options: CoordinatorOptions) {
    this.averageScanMs = options.initialScanEstimateMs
    this.now = options.now ?? Date.now
  }

  /** Whether a job for this target is already queued or running. */
  has(key: string): boolean {
    return this.jobs.has(key)
  }

  /**
   * Admit a visitor: join the existing job for this target, start a new one,
   * queue it, or refuse with the reason.
   *
   * `allowQueue: false` is for the one-shot JSON API, whose caller is a script
   * that retries rather than a person watching a line.
   */
  subscribe(
    target: QueueTarget,
    clientId: string,
    send: (event: QueueEvent) => void,
    { allowQueue = true }: { allowQueue?: boolean } = {},
  ): Admission {
    const existing = this.jobs.get(target.key)
    if (existing) {
      const subscriber = this.attach(existing, send)
      /* A late joiner gets the job as it stands: its place in line, or every
         stage it has reached and the recent measurements, so the live hero
         repaints from the same evidence the first visitor watched arrive. */
      send({ type: 'shared', viewers: existing.subscribers.size, state: existing.state })
      if (existing.state === 'queued') {
        this.sendPosition(existing, subscriber)
      } else {
        send({ type: 'started' })
        for (const stage of existing.stages.values()) send({ type: 'stage', stage })
        for (const observation of existing.observations) send({ type: 'observation', observation })
      }
      return { admitted: true, created: false, unsubscribe: () => this.detach(existing, subscriber.id) }
    }

    const slotFree = this.running < this.options.maxConcurrent
    if (!slotFree && !allowQueue) {
      return {
        admitted: false,
        code: 'SCANNER_BUSY',
        message: 'The public scanner is at capacity. Please retry in a few seconds.',
        retryAfterSeconds: this.secondsUntilASlotFrees(),
      }
    }
    /* The per-client share applies only when the scan would have to WAIT. With
       a slot free there is nobody to be unfair to, so an office behind one NAT
       address is limited by the rate limit alone; under load one address can
       hold no more than its share of the line. */
    if (!slotFree) {
      const active = [...this.jobs.values()].filter((job) => job.createdBy === clientId).length
      if (active >= this.options.maxActivePerClient) {
        return {
          admitted: false,
          code: 'CLIENT_BUSY',
          message: `The public scanner is at capacity and you already have ${active} assessment${active === 1 ? '' : 's'} waiting or running. While others are waiting, each visitor may hold ${this.options.maxActivePerClient} — this one can join the line as soon as one of yours finishes.`,
          retryAfterSeconds: this.secondsUntilASlotFrees(),
        }
      }
    }
    if (!slotFree && this.queue.length >= this.options.maxQueue) {
      return {
        admitted: false,
        code: 'QUEUE_FULL',
        message: `The public scanner is at capacity and its waiting line is full (${this.options.maxQueue} assessments). A place opens in about ${this.secondsUntilASlotFrees()} seconds.`,
        retryAfterSeconds: this.secondsUntilASlotFrees(),
      }
    }

    const job: Job = {
      target,
      state: 'queued',
      subscribers: new Map(),
      createdBy: clientId,
      controller: new AbortController(),
      queuedAt: this.now(),
      startedAt: null,
      stages: new Map(),
      observations: [],
      graceTimer: null,
      abortReason: null,
    }
    this.jobs.set(target.key, job)
    const subscriber = this.attach(job, send)

    if (slotFree) {
      this.start(job)
    } else {
      this.queue.push(job)
      this.sendPosition(job, subscriber)
    }
    return { admitted: true, created: true, unsubscribe: () => this.detach(job, subscriber.id) }
  }

  stats(): QueueStats {
    let viewers = 0
    for (const job of this.jobs.values()) viewers += job.subscribers.size
    return {
      capacity: this.options.maxConcurrent,
      running: this.running,
      queued: this.queue.length,
      queueCapacity: this.options.maxQueue,
      viewers,
      averageScanSeconds: Math.round(this.averageScanMs / 1000),
      ...this.counters,
    }
  }

  /* ── subscribers ─────────────────────────────────────────────────────── */

  private attach(job: Job, send: (event: QueueEvent) => void): Subscriber {
    const subscriber: Subscriber = { id: this.nextSubscriberId++, send }
    job.subscribers.set(subscriber.id, subscriber)
    if (job.graceTimer) {
      clearTimeout(job.graceTimer)
      job.graceTimer = null
    }
    return subscriber
  }

  private detach(job: Job, subscriberId: number): void {
    if (!job.subscribers.delete(subscriberId)) return
    if (job.subscribers.size > 0 || this.jobs.get(job.target.key) !== job) return
    /* Nobody is watching. Wait out a reload or a reconnect before giving the
       place up — then withdraw a waiting job, or stop a running scan so its
       slot goes to someone who is still here. */
    job.graceTimer = setTimeout(() => {
      job.graceTimer = null
      if (job.subscribers.size > 0 || this.jobs.get(job.target.key) !== job) return
      this.counters.abandoned += 1
      if (job.state === 'queued') {
        this.jobs.delete(job.target.key)
        const index = this.queue.indexOf(job)
        if (index >= 0) this.queue.splice(index, 1)
        this.broadcastPositions()
      } else {
        job.abortReason = 'abandoned'
        job.controller.abort()
      }
    }, this.options.abandonGraceMs)
  }

  private fanOut(job: Job, event: QueueEvent): void {
    for (const subscriber of job.subscribers.values()) {
      try {
        subscriber.send(event)
      } catch {
        /* A dead connection is the route's to clean up; it must not stop the
           event reaching everyone else watching this job. */
      }
    }
  }

  /* ── execution ───────────────────────────────────────────────────────── */

  private start(job: Job): void {
    job.state = 'running'
    job.startedAt = this.now()
    this.running += 1
    this.fanOut(job, { type: 'started' })

    const timer = setTimeout(() => {
      job.abortReason = 'timeout'
      job.controller.abort()
    }, this.options.timeoutMs)

    const hooks: RunHooks = {
      signal: job.controller.signal,
      onStage: (stage) => {
        if (job.controller.signal.aborted) return
        job.stages.set(stage.key, stage)
        this.fanOut(job, { type: 'stage', stage })
      },
      onObservation: (observation) => {
        if (job.controller.signal.aborted) return
        job.observations.push(observation)
        if (job.observations.length > REPLAY_OBSERVATIONS) job.observations.shift()
        this.fanOut(job, { type: 'observation', observation })
      },
    }
    /* A scan that throws before returning its promise must still settle the
       job and release the slot — `pump()` runs inside `finally`, and an
       exception escaping here would leave the count incremented forever. */
    let run: Promise<PublicScanReport>
    try {
      run = this.options.run(job.target, hooks)
    } catch (error) {
      run = Promise.reject(error)
    }

    /* The abort is raced too: a scan that ignores its signal still releases its
       slot when it is abandoned or times out, rather than holding it until the
       engines happen to notice. */
    const aborted = new Promise<never>((_resolve, reject) => {
      job.controller.signal.addEventListener('abort', () => reject(new Error('aborted')), { once: true })
    })

    void Promise.race([run, aborted])
      .then((report) => {
        const durationMs = this.now() - (job.startedAt ?? this.now())
        this.averageScanMs = Math.round(this.averageScanMs * 0.7 + durationMs * 0.3)
        this.counters.completed += 1
        this.options.onReport?.(job.target, report, durationMs)
        this.fanOut(job, { type: 'complete', report })
      })
      .catch((error: unknown) => {
        const durationMs = this.now() - (job.startedAt ?? this.now())
        if (job.abortReason === 'abandoned') return
        if (job.abortReason !== 'timeout' && this.options.isCancellation?.(error)) return
        const message = job.abortReason === 'timeout'
          ? 'Assessment exceeded the public scan time budget.'
          : error instanceof Error ? error.message : 'The assessment could not be completed.'
        this.counters.failed += 1
        this.options.onFailure?.(job.target, message, durationMs)
        this.fanOut(job, { type: 'failed', message })
      })
      .finally(() => {
        clearTimeout(timer)
        if (job.graceTimer) clearTimeout(job.graceTimer)
        /* Swallow the engines' own late rejection after an abort won the race. */
        run.catch(() => undefined)
        if (this.jobs.get(job.target.key) === job) this.jobs.delete(job.target.key)
        this.running -= 1
        this.pump()
      })
  }

  private pump(): void {
    let changed = false
    while (this.running < this.options.maxConcurrent && this.queue.length > 0) {
      this.start(this.queue.shift()!)
      changed = true
    }
    if (changed) this.broadcastPositions()
  }

  /* ── the line ────────────────────────────────────────────────────────── */

  /**
   * When each queued job is expected to start, in ms from now.
   *
   * Simulated against real state: every running slot frees when its scan
   * reaches the measured average duration (never sooner than a second from
   * now), each queued job takes the earliest free slot, and holds it for one
   * average scan. An estimate, and labelled as one wherever it is shown.
   */
  private startEstimates(): number[] {
    const now = this.now()
    const slots: number[] = []
    for (const job of this.jobs.values()) {
      if (job.state !== 'running' || job.startedAt === null) continue
      slots.push(Math.max(1_000, this.averageScanMs - (now - job.startedAt)))
    }
    while (slots.length < this.options.maxConcurrent) slots.push(0)
    return this.queue.map(() => {
      let earliest = 0
      for (let index = 1; index < slots.length; index += 1) if (slots[index] < slots[earliest]) earliest = index
      const startsIn = slots[earliest]
      slots[earliest] = startsIn + this.averageScanMs
      return startsIn
    })
  }

  private secondsUntilASlotFrees(): number {
    const now = this.now()
    let soonest = this.averageScanMs
    for (const job of this.jobs.values()) {
      if (job.state === 'running' && job.startedAt !== null) {
        soonest = Math.min(soonest, Math.max(1_000, this.averageScanMs - (now - job.startedAt)))
      }
    }
    return Math.max(5, Math.min(120, Math.ceil(soonest / 1000)))
  }

  private positionEvent(index: number, estimates: number[]): QueueEvent {
    return {
      type: 'queued',
      position: index + 1,
      queueLength: this.queue.length,
      estimatedWaitSeconds: Math.max(1, Math.ceil((estimates[index] ?? this.averageScanMs) / 1000)),
      running: this.running,
      capacity: this.options.maxConcurrent,
    }
  }

  private sendPosition(job: Job, subscriber: Subscriber): void {
    const index = this.queue.indexOf(job)
    if (index < 0) return
    try {
      subscriber.send(this.positionEvent(index, this.startEstimates()))
    } catch {
      /* see fanOut */
    }
  }

  private broadcastPositions(): void {
    if (this.queue.length === 0) return
    const estimates = this.startEstimates()
    this.queue.forEach((job, index) => this.fanOut(job, this.positionEvent(index, estimates)))
  }
}
