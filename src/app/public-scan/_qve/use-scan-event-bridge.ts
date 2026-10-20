/**
 * Quantum Visualization Engine™ — SSE bridge.
 *
 * Binds the real `usePublicScan` stream to the engine's event store. This is the
 * only module that knows both sides, which is what keeps the visualization
 * reusable: swap this hook for a different bridge and the same engine renders a
 * dashboard scan, a migration run or a SOC feed.
 *
 * PACING NOTE (read before "simplifying" the release queue):
 * The backend delivers its six workflow stages as they happen, then the whole
 * evidence bundle in a single `scan-complete` frame. Ingesting ~25 evidence
 * events in one tick would collapse the timeline into a single jump and give the
 * packet engine nothing to animate. The queue therefore *releases already
 * received, already real events* over successive animation frames. It never
 * fabricates an event, never advances progress on its own and never runs when
 * the store is idle — it only spaces out the presentation of facts the scanner
 * has already returned. Under `prefers-reduced-motion` the queue drains in one
 * frame.
 */
'use client';

import React from 'react';
import type { PublicScanReport, PublicScanStage } from '@/lib/scanner/public-scan/types';
import type { UsePublicScanResult } from '@/hooks/use-public-scan';
import {
  nodeScoresFromReport,
  observationEvent,
  reportEvidenceEvents,
  scanEndedEvent,
  scanStartedEvent,
  stageTransitionEvents,
} from './event-derivation';
import { useQve } from './scan-event-store';
import type { ScanEvent } from './types';

/** Milliseconds between released evidence events. */
const RELEASE_INTERVAL_MS = 110;

export interface ScanEventBridgeInput {
  state: UsePublicScanResult['state'];
  stages: PublicScanStage[];
  report: PublicScanReport | null;
  /** Live measurements streamed during the run. */
  observations: UsePublicScanResult['observations'];
  progress: number;
  /** Why the run ended without a report, in the server's words when it gave them. */
  error: string | null;
  /** True when the server declined to start the run at all. */
  refused: boolean;
  /** Host or URL being assessed, for the `asset` field. */
  asset: string;
  /** True when heavy motion is disabled — drains the queue immediately. */
  reducedMotion: boolean;
}

export function useScanEventBridge({
  state,
  stages,
  report,
  observations,
  progress,
  error,
  refused,
  asset,
  reducedMotion,
}: ScanEventBridgeInput): void {
  const { dispatch } = useQve();

  const previousStates = React.useRef(new Map<string, PublicScanStage['state']>());
  const previousRunState = React.useRef<typeof state>('idle');
  const reportedScanId = React.useRef<string | null>(null);
  const consumedObservations = React.useRef(0);
  const queue = React.useRef<ScanEvent[]>([]);
  const timer = React.useRef<number | null>(null);

  /** Drain helper — one event per interval, or all at once when reduced. */
  const pump = React.useCallback(() => {
    if (timer.current !== null) return;
    const step = () => {
      const next = queue.current.shift();
      if (!next) {
        timer.current = null;
        return;
      }
      dispatch({ type: 'ingest', event: next });
      timer.current = window.setTimeout(step, RELEASE_INTERVAL_MS);
    };
    timer.current = window.setTimeout(step, 0);
  }, [dispatch]);

  const enqueue = React.useCallback(
    (events: ScanEvent[]) => {
      if (!events.length) return;
      if (reducedMotion) {
        for (const event of events) dispatch({ type: 'ingest', event });
        return;
      }
      queue.current.push(...events);
      pump();
    },
    [dispatch, pump, reducedMotion],
  );

  const clearQueue = React.useCallback(() => {
    queue.current = [];
    if (timer.current !== null) {
      window.clearTimeout(timer.current);
      timer.current = null;
    }
  }, []);

  React.useEffect(() => clearQueue, [clearQueue]);

  /* ── Run lifecycle ─────────────────────────────────────────────────────── */

  React.useEffect(() => {
    const previous = previousRunState.current;
    previousRunState.current = state;
    if (previous === state) return;

    if (state === 'scanning') {
      clearQueue();
      previousStates.current.clear();
      reportedScanId.current = null;
      consumedObservations.current = 0;
      dispatch({ type: 'reset' });
      dispatch({ type: 'ingest', event: scanStartedEvent(asset) });
    } else if (state === 'idle') {
      clearQueue();
      previousStates.current.clear();
      reportedScanId.current = null;
      consumedObservations.current = 0;
      dispatch({ type: 'reset' });
    } else if (state === 'error') {
      /* The run ended without a report. Say so in the engine too, or the hero
         keeps animating a scan that is not happening. A refusal that arrives
         in the same batch as the start skips `scanning`, so a previous run's
         verdicts are cleared first rather than shown beside the refusal. */
      if (previous !== 'scanning') dispatch({ type: 'reset' });
      dispatch({
        type: 'ingest',
        event: scanEndedEvent(asset, error ?? 'The assessment could not be completed.', refused),
      });
    }
    // `asset`, `error` and `refused` are read at transition time only; a later
    // edit to the input must not retroactively restamp a running scan.
    // eslint-disable-next-line react-hooks/exhaustive-deps
  }, [state, clearQueue, dispatch]);

  /* ── Stage frames (real SSE) ───────────────────────────────────────────── */

  React.useEffect(() => {
    /* `complete` is included deliberately. A CACHED result replays every stage
       frame and `scan-complete` inside one React batch, so by the time this
       effect ran the state had already flipped to `complete` and every stage
       transition was dropped — the six surface cards sat on "Standby" under a
       finished report. Settled transitions are real information whenever they
       arrive; `mergeNodeState` already stops a late frame from regressing a
       card, so ingesting them here cannot fight the report-derived events. */
    if (state !== 'scanning' && state !== 'complete') return;
    const derived: ScanEvent[] = [];
    for (const stage of stages) {
      const previous = previousStates.current.get(stage.key);
      const events = stageTransitionEvents(stage, previous, progress, asset);
      previousStates.current.set(stage.key, stage.state);
      derived.push(...events);
    }
    // Stage frames are the live pulse of the scan — deliver them immediately so
    // node cards light up the moment the backend says the module started.
    for (const event of derived) dispatch({ type: 'ingest', event });
    // eslint-disable-next-line react-hooks/exhaustive-deps
  }, [stages, state, progress, dispatch]);

  /* ── Live observations (real, streamed as measured) ────────────────────── */

  React.useEffect(() => {
    // A reset shrinks the array — rewind rather than replaying history.
    if (observations.length < consumedObservations.current) consumedObservations.current = 0;
    if (observations.length === consumedObservations.current) return;

    for (let index = consumedObservations.current; index < observations.length; index += 1) {
      // Dispatched immediately, never queued: these already arrived at the
      // scanner's own pace, and re-spacing them would replace a real cadence
      // with an invented one.
      dispatch({ type: 'ingest', event: observationEvent(observations[index], progress, asset) });
    }
    consumedObservations.current = observations.length;
    // `progress` and `asset` are read at dispatch time; re-running on their
    // change alone would re-emit observations already consumed.
    // eslint-disable-next-line react-hooks/exhaustive-deps
  }, [observations, dispatch]);

  /* ── Completed report (real evidence) ──────────────────────────────────── */

  React.useEffect(() => {
    if (!report || reportedScanId.current === report.scanId) return;
    reportedScanId.current = report.scanId;
    enqueue(reportEvidenceEvents(report));
    dispatch({
      type: 'settle',
      grade: report.executive.gradeable ? report.executive.grade : null,
      gradeColor: report.executive.gradeColor,
      score: report.executive.encryptionScore,
      postQuantumScore: report.executive.postQuantumReadiness,
      nodeScores: nodeScoresFromReport(report),
    });
  }, [report, enqueue, dispatch]);
}
