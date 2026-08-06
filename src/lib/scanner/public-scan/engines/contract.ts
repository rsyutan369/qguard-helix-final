/**
 * QGuard Helix — Public Scan Intelligence Engine™
 * Shared module contract.
 *
 * The scanner is a framework of independent, reusable engines rather than a
 * single monolithic scanner (Scanning_Engine_Framework). Every engine:
 *   • runs independently and asynchronously
 *   • owns its own timeouts, retries and transport fallbacks
 *   • never throws — a failed probe is a *result* (`Unknown`), not an exception
 *   • returns structured evidence with a detection method and a confidence
 *
 * STATUS SEMANTICS (Public_Scan_Intelligence_Engines)
 * ---------------------------------------------------
 * The four negative states are NOT interchangeable, and conflating them is the
 * single most common way a scanner ends up lying:
 *
 *   Unknown         The engine tried and could not reach a reliable conclusion.
 *                   Timeout, DNS failure, partial handshake, CDN interference.
 *   Not Observable  The property cannot be determined from *any* external scan.
 *                   Internal HSM, source code, database encryption, governance.
 *   Not Supported   The control was expected and is genuinely absent.
 *                   Missing HSTS, missing CAA, no OCSP staple, no SCTs.
 *   Not Applicable  The control is irrelevant for the scanned service.
 *
 * "We could not measure it" must never render as "they failed it".
 */

export type ControlStatus =
  | 'Healthy'
  | 'Warning'
  | 'Critical'
  | 'Unknown'
  | 'Not Observable'
  | 'Not Supported'
  | 'Not Applicable'

/** Statuses that represent a real, measured verdict about the target. */
export const MEASURED_STATUSES: ReadonlySet<ControlStatus> = new Set<ControlStatus>([
  'Healthy',
  'Warning',
  'Critical',
  'Not Supported',
])

/** Statuses that mean "this scan did not establish a value". */
export const UNMEASURED_STATUSES: ReadonlySet<ControlStatus> = new Set<ControlStatus>([
  'Unknown',
  'Not Observable',
  'Not Applicable',
])

export function isMeasured(status: ControlStatus): boolean {
  return MEASURED_STATUSES.has(status)
}

/** How a value was obtained. Printed alongside every finding as provenance. */
export type DetectionMethod =
  | 'TLS handshake'
  | 'TLS named-group probe'
  | 'TLS protocol probe'
  | 'TLS cipher probe'
  | 'X.509 certificate'
  | 'X.509 extension'
  | 'Chain verification'
  | 'OCSP staple'
  | 'HTTP response header'
  | 'HTTP response metadata'
  | 'DNS query'
  | 'DNS-over-HTTPS query'
  | 'Derived'

/**
 * One structured observation. Every finding surfaced to the user carries these
 * fields so the number on screen can always be traced back to a measurement.
 */
export interface Evidence {
  /** What was measured. */
  label: string
  /** The raw observed value, verbatim where possible. */
  observedValue: string
  detectionMethod: DetectionMethod
  /** Where the value came from, e.g. "cloudflare-dns.com (DoH)" or "leaf certificate". */
  evidenceSource: string
  /** 0-100. Reflects transport reliability, not how good the result is. */
  confidence: number
}

/* ─── Live observations ─────────────────────────────────────────────────────── */

/**
 * The six surfaces the public hero renders around the core. An observation is
 * addressed to one of them so the UI can route it without knowing anything
 * about engine internals.
 */
export type ObservationSurface = 'dns' | 'tls' | 'certificate' | 'headers' | 'ocsp' | 'quantum'

/**
 * A single measurement, emitted AT THE MOMENT IT IS MADE.
 *
 * Engines return their full result when they finish, which is correct for the
 * report but useless for a live view: a named-group phase that takes fourteen
 * sequential handshakes reports fourteen real facts over ten seconds and then
 * used to deliver all of them in one frame at the end. Streaming them keeps the
 * honesty contract intact — nothing here is generated, scheduled or paced; each
 * frame is emitted by the code path that just performed the measurement, and
 * carries the wall-clock time at which it happened.
 */
export interface ScanObservation {
  surface: ObservationSurface
  /** What was measured, e.g. "X25519MLKEM768". */
  label: string
  /** What came back, in the operator's language. */
  detail: string
  /** Verdict for this single measurement. */
  status: 'pass' | 'warning' | 'critical' | 'info'
  severity: 'none' | 'info' | 'low' | 'medium' | 'high' | 'critical'
  /**
   * Headline word for the surface, e.g. "Secure" / "Not stapled". Set only by
   * the observation that is the surface's PRIMARY finding — a per-group probe
   * result is real evidence but it is not the verdict on the whole surface, and
   * letting it rewrite the headline would make the card flicker through eleven
   * different words during one enumeration.
   */
  verdict?: string
  /** True when this observation is post-quantum evidence. */
  postQuantum?: boolean
  /**
   * Real completion counts for a phase that makes many measurements.
   *
   * The named-group phase performs dozens of handshakes inside ONE workflow
   * stage. Without this the UI can only show that stage as "running" for its
   * whole duration, which reads as a stall even when evidence is arriving every
   * few hundred milliseconds. These are counts of work actually finished — never
   * a timer, never an estimate — so a bar driven by them cannot get ahead of the
   * scan or sit still while it is working.
   */
  progress?: { done: number; total: number }
  /** Epoch ms at which the measurement completed. */
  at: number
}

/** Sink an engine writes live measurements to. Always optional. */
export type ObservationSink = (observation: Omit<ScanObservation, 'at'> & { at?: number }) => void

/** Wraps a sink so every observation is stamped and a throwing sink is contained. */
export function observationEmitter(sink?: ObservationSink): ObservationSink {
  return (observation) => {
    if (!sink) return
    try {
      sink({ ...observation, at: observation.at ?? Date.now() })
    } catch {
      /* A broken consumer must never fail the scan. */
    }
  }
}

/** Result envelope every engine returns. */
export interface EngineResult<T> {
  engine: string
  /** Populated payload. Always present — engines return empty shapes, not null. */
  data: T
  /** Whether the engine reached a usable conclusion at all. */
  ok: boolean
  /** Overall confidence in this engine's output (0-100). */
  confidence: number
  /** Structured observations for the evidence drawer. */
  evidence: Evidence[]
  /** Non-fatal notes: fallbacks used, partial results, throttling seen. */
  notes: string[]
  /** Populated only when the engine could not run at all. */
  error: string | null
  durationMs: number
}

export function emptyResult<T>(engine: string, data: T, error: string | null = null): EngineResult<T> {
  return {
    engine,
    data,
    ok: false,
    confidence: 0,
    evidence: [],
    notes: [],
    error,
    durationMs: 0,
  }
}

/** Wrap an engine so a thrown error becomes a result rather than killing the scan. */
export async function runEngine<T>(
  engine: string,
  fallback: T,
  fn: () => Promise<Omit<EngineResult<T>, 'engine' | 'durationMs'>>,
): Promise<EngineResult<T>> {
  const startedAt = Date.now()
  try {
    const result = await fn()
    return { ...result, engine, durationMs: Date.now() - startedAt }
  } catch (err) {
    return {
      ...emptyResult(engine, fallback, (err as Error).message),
      durationMs: Date.now() - startedAt,
    }
  }
}

/** Bounded promise: resolves to `fallback` instead of hanging or rejecting. */
export function withTimeout<T>(promise: Promise<T>, ms: number, fallback: T): Promise<T> {
  return new Promise((resolve) => {
    let settled = false
    const timer = setTimeout(() => {
      if (settled) return
      settled = true
      resolve(fallback)
    }, ms)
    promise
      .then((value) => {
        if (settled) return
        settled = true
        clearTimeout(timer)
        resolve(value)
      })
      .catch(() => {
        if (settled) return
        settled = true
        clearTimeout(timer)
        resolve(fallback)
      })
  })
}

/**
 * Retry a probe once when the failure looks transient (reset / timeout) rather
 * than a real negative answer. CDNs reset probe connections under load often
 * enough that a single attempt produces false negatives.
 */
export async function retryTransient<T>(
  attempt: () => Promise<T>,
  isSuccess: (value: T) => boolean,
  delayMs = 300,
): Promise<T> {
  const first = await attempt()
  if (isSuccess(first)) return first
  await new Promise((resolve) => setTimeout(resolve, delayMs))
  const second = await attempt()
  return isSuccess(second) ? second : first
}

export const clampScore = (value: number) => Math.max(0, Math.min(100, Math.round(value)))
