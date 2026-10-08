/**
 * Stage timing for the two pipelines whose latency users actually feel: opening
 * encrypted history, and establishing a call.
 *
 * Both failures this module exists to make visible looked identical from the
 * outside ("it just hangs") while having completely different causes — a
 * network round trip with no deadline in one case, an ICE agent that never
 * finished gathering in the other. Neither was diagnosable from the UI, and
 * both were diagnosed only by reconstructing timings after the fact from
 * database rows. Recording the stages as they happen turns that archaeology
 * into a single log line.
 *
 * Deliberately pure + synchronous: a timeline is a plain value, every function
 * takes `now` so tests control the clock, and nothing here touches the network.
 * The ring buffer is the only state, so an instrumented pipeline cannot leak
 * memory or change behaviour by being observed.
 */

/** Stage names for opening encrypted history. */
export const HISTORY_STAGES = {
  loadStart: "history_load_start",
  cacheRendered: "cache_rendered",
  fetchStart: "fetch_start",
  fetchComplete: "fetch_complete",
  decryptStart: "decrypt_start",
  decryptComplete: "decrypt_complete",
  rendered: "history_rendered",
} as const;

/** Stage names for establishing a call. */
export const CALL_STAGES = {
  initiated: "call_initiated",
  signalingStarted: "signaling_started",
  iceStarted: "ICE_started",
  iceConnected: "ICE_connected",
  mediaConnected: "media_connected",
  established: "call_established",
} as const;

export type TimelineKind = "history" | "call";

export type TimelineOutcome =
  /** Reached its terminal stage. */
  | "ok"
  /** A deadline fired before the terminal stage. */
  | "timeout"
  /** Failed with an error. */
  | "error"
  /** Superseded or cancelled — a newer load won the race, or the user left. */
  | "abandoned";

export interface TimelineMark {
  readonly stage: string;
  /** Milliseconds since the timeline started. */
  readonly atMs: number;
}

export interface Timeline {
  readonly kind: TimelineKind;
  /** Conversation id or call id — whatever makes the timeline findable. */
  readonly id: string;
  readonly startedAtMs: number;
  marks: TimelineMark[];
  outcome: TimelineOutcome | null;
  /** Total duration once complete. */
  totalMs: number | null;
  /** Free-form context for the log line (row counts, relay health, …). */
  detail: Record<string, string | number | boolean>;
}

export function createTimeline(kind: TimelineKind, id: string, nowMs: number): Timeline {
  return { kind, id, startedAtMs: nowMs, marks: [], outcome: null, totalMs: null, detail: {} };
}

/**
 * Record a stage.
 *
 * First write wins per stage: a stage that can be reached by more than one path
 * (a decrypt that completes from cache on one group and from the backend on the
 * next) should report when the pipeline FIRST got there, and a retry must not
 * rewrite history. Marks after completion are ignored outright.
 */
export function markTimeline(timeline: Timeline, stage: string, nowMs: number): void {
  if (timeline.outcome !== null) return;
  if (timeline.marks.some((mark) => mark.stage === stage)) return;
  timeline.marks.push({ stage, atMs: Math.max(0, nowMs - timeline.startedAtMs) });
}

/** Attach context that explains the numbers (row count, cache hit, …). */
export function describeTimeline(
  timeline: Timeline,
  detail: Record<string, string | number | boolean>,
): void {
  Object.assign(timeline.detail, detail);
}

/** Close a timeline. Idempotent — the first outcome is the real one. */
export function completeTimeline(timeline: Timeline, outcome: TimelineOutcome, nowMs: number): Timeline {
  if (timeline.outcome !== null) return timeline;
  timeline.outcome = outcome;
  timeline.totalMs = Math.max(0, nowMs - timeline.startedAtMs);
  return timeline;
}

/** Milliseconds between two recorded stages, or null when either is missing. */
export function stageDeltaMs(timeline: Timeline, fromStage: string, toStage: string): number | null {
  const from = timeline.marks.find((mark) => mark.stage === fromStage);
  const to = timeline.marks.find((mark) => mark.stage === toStage);
  if (!from || !to) return null;
  return to.atMs - from.atMs;
}

/** Elapsed time at a stage, or null when it was never reached. */
export function stageAtMs(timeline: Timeline, stage: string): number | null {
  return timeline.marks.find((mark) => mark.stage === stage)?.atMs ?? null;
}

/** One grep-able line: `[perf] history 66f6662a ok total=842ms  load=0 …`. */
export function formatTimeline(timeline: Timeline): string {
  const stages = timeline.marks.map((mark) => `${mark.stage}=${Math.round(mark.atMs)}`).join(" ");
  const detail = Object.entries(timeline.detail).map(([key, value]) => `${key}=${value}`).join(" ");
  const total = timeline.totalMs === null ? "open" : `${Math.round(timeline.totalMs)}ms`;
  return [
    `[perf] ${timeline.kind} ${timeline.id.slice(0, 8)}`,
    `${timeline.outcome ?? "open"} total=${total}`,
    stages,
    detail,
  ].filter(Boolean).join(" ");
}

// ---------------------------------------------------------------------------
// Ring buffer
// ---------------------------------------------------------------------------

const MAX_RETAINED = 40;
const retained: Timeline[] = [];
type TimelineListener = (timeline: Timeline) => void;
const listeners = new Set<TimelineListener>();

/**
 * Publish a completed timeline: retain it for inspection, log it once, and
 * notify any listener.
 *
 * Only completed timelines are published. An open timeline has no outcome and
 * no total, so logging one would report a pipeline as finished while it is
 * still running — which is exactly the kind of false reassurance this module
 * is meant to replace.
 */
export function publishTimeline(timeline: Timeline): void {
  if (timeline.outcome === null) return;
  retained.push(timeline);
  while (retained.length > MAX_RETAINED) retained.shift();
  // A slow or failed pipeline is the interesting one, so it gets a warning the
  // user can be asked to read back; a healthy one stays at debug volume.
  const line = formatTimeline(timeline);
  if (timeline.outcome === "ok") console.debug(line);
  else if (timeline.outcome === "abandoned") console.debug(line);
  else console.warn(line);
  listeners.forEach((listener) => {
    try {
      listener(timeline);
    } catch {
      // A broken observer must never break the pipeline it is observing.
    }
  });
}

/** Completed timelines, newest last. Optionally filtered by kind. */
export function recentTimelines(kind?: TimelineKind): readonly Timeline[] {
  return kind ? retained.filter((timeline) => timeline.kind === kind) : [...retained];
}

/** Subscribe to completed timelines. Returns an unsubscribe function. */
export function onTimeline(listener: TimelineListener): () => void {
  listeners.add(listener);
  return () => listeners.delete(listener);
}

/** Test seam: drop retained timelines. */
export function resetTimelines(): void {
  retained.length = 0;
}
