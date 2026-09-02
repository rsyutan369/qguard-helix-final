/**
 * Scan telemetry frames — the ONE translation from `ScanEvent` to a console line.
 *
 * The Quantum Scan Theatre renders a live telemetry feed. That feed must be the
 * scan talking, not the UI narrating: every line here is built from a real
 * event emitted by a real engine, carries that event's own timestamp, and says
 * only what the event said.
 *
 * Both modes go through this module on purpose. LOCAL receives events from a
 * Web Worker and DEV receives them over SSE, but they are the same `ScanEvent`
 * shape produced by the same orchestrator — so if the two panels formatted them
 * separately they would drift, and the same scan would read differently
 * depending on where it ran.
 *
 * ISOMORPHIC: imports only the domain model. No DOM, no Node.
 */

import type { FindingSeverity, ScanEvent } from './types';

/* ─────────────────────────────────────────────────────────────── the frame ── */

/**
 * Console severity of a frame. Deliberately NOT finding severity — a frame is
 * about the SCAN (an engine failed, a dimension could not be read), while
 * `severity` below is about the finding the frame reports.
 */
export type TelemetryLevel = 'info' | 'ok' | 'warn' | 'error' | 'detect';

export interface ScanTelemetryFrame {
  /** Monotonic within a scan. Used as the React key — timestamps collide. */
  seq: number;
  /** The event's OWN timestamp, never the time the UI happened to render it. */
  at: string;
  level: TelemetryLevel;
  text: string;
  engineId?: string;
  engineLabel?: string;
  /** Present only on `detect` frames: the severity of the reported finding. */
  severity?: FindingSeverity;
  findingId?: string;
  /** The artefact the engine named, when it named one (a path, image, namespace). */
  artifact?: string;
  /** Real unit counts, when the engine reported them. */
  units?: { done: number; total: number; unit: string };
}

/** Bounded ring: a deep scan emits tens of thousands of progress events, and a
 *  console that keeps all of them is a memory leak with a scrollbar. */
export const TELEMETRY_LIMIT = 240;

/* ────────────────────────────────────────────────────────────── artefacts ─── */

/**
 * Pulls the artefact out of an engine step.
 *
 * Steps are written by the engines as `Analysing src/tls/client.ts`,
 * `Reading namespace payments`, `Inspecting ghcr.io/acme/api:1.4`. The last
 * token is the artefact whenever it looks like one; otherwise there is no
 * artefact and the caller shows the step alone. Nothing is invented — a step
 * with no path yields `undefined`.
 */
export function artifactFromStep(step: string | undefined): string | undefined {
  if (!step) return undefined;
  const token = step.trim().split(/\s+/).pop();
  if (!token || token.length < 3) return undefined;
  if (!/[/\\.:]/.test(token)) return undefined;
  // Trailing punctuation from a sentence-shaped step is not part of the path.
  const cleaned = token.replace(/[.,;:]+$/, '');
  return cleaned.length >= 3 ? cleaned : undefined;
}

/* ─────────────────────────────────────────────────────────── translation ──── */

const ENGINE_STATE_LEVEL: Record<string, TelemetryLevel> = {
  completed: 'ok',
  failed: 'error',
  skipped: 'info',
  'not-applicable': 'info',
  'not-assessed': 'warn',
  cancelled: 'warn',
};

/**
 * Builds the frame for one event, or `null` when the event carries nothing a
 * reader could act on.
 *
 * `seq` is supplied by the caller because it belongs to the stream, not the
 * event: the same event replayed on SSE reconnect must not claim a new place in
 * the console.
 */
export function toTelemetryFrame(event: ScanEvent, seq: number): ScanTelemetryFrame | null {
  const base = {
    seq,
    at: event.timestamp,
    engineId: event.engineId,
    engineLabel: event.engineLabel,
  };

  switch (event.event) {
    case 'scan.created':
    case 'scan.started':
      return { ...base, level: 'info', text: event.message ?? 'Assessment started' };

    case 'engine.started':
      return {
        ...base,
        level: 'info',
        text: `${event.engineLabel ?? event.engineId ?? 'Engine'} engaged${event.step ? ` — ${event.step}` : ''}`,
        artifact: artifactFromStep(event.step),
      };

    case 'engine.progress': {
      if (!event.step) return null;
      return {
        ...base,
        level: 'info',
        text: `${event.engineLabel ?? event.engineId ?? 'Engine'}: ${event.step}`,
        artifact: artifactFromStep(event.step),
        units: event.units,
      };
    }

    case 'finding.discovered': {
      const finding = event.finding;
      if (!finding) return null;
      const where = finding.evidence[0]?.file ?? finding.evidence[0]?.scope;
      return {
        ...base,
        level: 'detect',
        severity: finding.severity,
        findingId: finding.id,
        text: finding.title,
        artifact: where ?? undefined,
      };
    }

    case 'evidence.collected':
      // This channel carries the `not assessed` disclosures. Absence of a
      // reading is a warning, never a quiet pass (§43).
      if (!event.detail) return null;
      return { ...base, level: 'warn', text: event.detail };

    case 'engine.completed':
    case 'engine.failed': {
      const state = event.state ?? (event.event === 'engine.failed' ? 'failed' : 'completed');
      const label = event.engineLabel ?? event.engineId ?? 'Engine';
      const verb =
        state === 'completed' ? 'complete'
          : state === 'failed' ? 'failed'
            : state === 'not-applicable' ? 'not applicable'
              : state === 'not-assessed' ? 'not assessed'
                : state === 'skipped' ? 'skipped'
                  : state;
      return {
        ...base,
        level: ENGINE_STATE_LEVEL[state] ?? 'info',
        text: `${label} ${verb}${event.detail ? ` — ${event.detail}` : ''}`,
      };
    }

    case 'correlation.completed':
    case 'scoring.completed':
      return { ...base, level: 'info', text: event.message ?? event.event };

    case 'scan.completed':
      return { ...base, level: 'ok', text: event.message ?? 'Assessment complete' };

    case 'scan.cancelled':
      return { ...base, level: 'warn', text: event.message ?? 'Assessment cancelled by operator' };

    case 'scan.failed':
      return {
        ...base,
        level: 'error',
        text: `${event.message ?? 'Assessment failed'}${event.detail ? ` — ${event.detail}` : ''}`,
      };

    default:
      return null;
  }
}

/**
 * Appends a frame to a bounded ring, collapsing an immediate repeat.
 *
 * Progress events from a per-file engine repeat the same sentence for every
 * file in a directory; showing the identical line twenty times in a row makes
 * the console look stalled when it is in fact the busiest it will ever be.
 */
export function appendTelemetry(
  current: ScanTelemetryFrame[],
  frame: ScanTelemetryFrame | null,
  limit = TELEMETRY_LIMIT,
): ScanTelemetryFrame[] {
  if (!frame) return current;
  const last = current[current.length - 1];
  if (last && last.text === frame.text && last.level === frame.level) return current;
  const next = current.length >= limit ? current.slice(current.length - limit + 1) : current.slice();
  next.push(frame);
  return next;
}
