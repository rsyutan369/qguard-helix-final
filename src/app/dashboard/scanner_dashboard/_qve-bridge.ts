/**
 * Dashboard Scanner — Quantum Visualization Engine™ bridge.
 *
 * Binds the authenticated `/api/v1/scanner/stream` run to the same event store
 * that drives the /public-scan hero. This is the only module that knows both
 * sides; the engine itself stays scan-agnostic.
 *
 * HONESTY CONTRACT (inherited from the public bridge, and non-negotiable here):
 * this hook NEVER fabricates an event and NEVER advances progress on its own.
 * It only *paces the presentation* of facts the scanner has already reported —
 * module state transitions, findings, the summary — so a burst of twenty
 * findings arriving in one SSE frame reads as a sequence instead of a single
 * jump. Under `prefers-reduced-motion` the queue drains in one frame.
 */
'use client';

import React from 'react';
import { useQve } from '@/app/public-scan/_qve';
import type { ScanEvent, ScanEventSeverity, ScanEventStatus } from '@/app/public-scan/_qve';
import { scoreToGrade } from '@/lib/scanner/public-scan/grading-model';
import { MODULE_NODE, nodeForFindingCategory } from './_intel';
import type { DefensiveFinding, ModuleState, ScanStatus, ScanSummary, ThreatLevel } from './_types';

/** Milliseconds between released events. Matches the public hero's cadence. */
const RELEASE_INTERVAL_MS = 110;

let sequence = 0;
function nextId(prefix: string): string {
  sequence += 1;
  return `${prefix}-${sequence}`;
}

const SEVERITY_FOR_THREAT: Record<ThreatLevel, ScanEventSeverity> = {
  CRITICAL: 'critical',
  HIGH: 'high',
  MEDIUM: 'medium',
  LOW: 'low',
  SAFE: 'info',
};

const STATUS_FOR_THREAT: Record<ThreatLevel, ScanEventStatus> = {
  CRITICAL: 'critical',
  HIGH: 'critical',
  MEDIUM: 'warning',
  LOW: 'warning',
  SAFE: 'pass',
};

function moduleEvent(module: ModuleState, progress: number): ScanEvent | null {
  const category = MODULE_NODE[module.id];
  if (!category) return null;

  const severity: ScanEventSeverity = module.status === 'Failed'
    ? 'high'
    : (module.severityCounts?.critical ?? 0) > 0
      ? 'critical'
      : (module.severityCounts?.high ?? 0) > 0
        ? 'high'
        : (module.severityCounts?.medium ?? 0) > 0
          ? 'medium'
          : 'info';

  const status: ScanEventStatus = module.status === 'Running'
    ? 'running'
    : module.status === 'Failed'
      ? 'failed'
      // A module that did not apply to the submitted targets is neutral, not a
      // pass. Painting "not applicable" the same green as "measured and clean"
      // is exactly the conflation the seven-state model exists to prevent.
      : module.status === 'Skipped'
        ? 'info'
        : severity === 'critical' || severity === 'high'
          ? 'critical'
          : severity === 'medium'
            ? 'warning'
            : 'pass';

  const line = module.status === 'Running'
    ? `${module.name} running`
    : module.status === 'Skipped'
      // The reason is the whole point of the state — a bare "not applicable"
      // is exactly what the operator complained about.
      ? `${module.name} not applicable: ${module.reason ?? 'no reason recorded'}`
      : module.status === 'Failed'
        ? (module.error ?? module.reason ?? `${module.name} failed`)
        : `${module.name}: ${module.findingsCount} finding${module.findingsCount === 1 ? '' : 's'}`;

  const running = module.status === 'Running';

  return {
    id: nextId(`module-${module.id}`),
    type: module.status === 'Failed' ? 'WARNING' : 'FINDING',
    timestamp: Date.now(),
    category,
    status,
    progress,
    severity,
    finding: line,
    asset: module.target,
    details: {
      /* Deliberately NO per-module verdict.
         A node card shows ONE surface, and a surface is fed by up to eight
         modules. Writing each module's own verdict into the node meant the card
         showed whichever module reported LAST — so a transport surface that had
         already collected four static-RSA cipher suites read "Secure" because
         its final module happened to be clean, while the accent colour (derived
         from peak severity) was red. The card's verdict is now resolved from
         the node's accumulated evidence by `resolveNodeVerdict`, which is the
         same function that produces the colour. */
      nodeLine: running ? null : line,
      nodeProgress: running ? 45 : 100,
      timelineLabel: line,
      timelineDetail: module.target,
      /**
       * A "Running" transition drives the card and the core, but it must NOT be
       * written to the assessment log.
       *
       * The log is append-only — an entry can never be updated once emitted —
       * so a `status: 'running'` line keeps its spinner forever. The backend
       * emits Running, then awaits a database write, then emits the terminal
       * state, which put a permanently-spinning "Asset inventory synchronizer
       * running" and "Audit/history logger running" in the log of every
       * completed scan. Across 22 modules that is 22 immortal spinners.
       *
       * The log therefore records settled observations only; live progress is
       * already carried by the node cards, the core and the workflow rail.
       */
      timeline: !running,
    },
  };
}

function findingEvent(finding: DefensiveFinding, progress: number): ScanEvent {
  return {
    id: nextId(`finding-${finding.id}`),
    type: 'FINDING',
    timestamp: Date.now(),
    category: nodeForFindingCategory(finding.category, finding.detectionMethod, finding.algorithm),
    status: STATUS_FOR_THREAT[finding.threatLevel],
    progress,
    severity: SEVERITY_FOR_THREAT[finding.threatLevel],
    finding: `${finding.algorithm} — ${finding.category}`,
    asset: finding.location,
    details: {
      // The card keeps module verdicts; a single finding contributes to the
      // timeline and the inspector but must not evict a module's headline.
      nodeLine: null,
      timelineLabel: `${finding.algorithm} · ${finding.threatLevel}`,
      timelineDetail: finding.location,
      postQuantum: /ml-kem|ml-dsa|kyber|dilithium|slh-dsa|sphincs/i.test(finding.algorithm),
    },
  };
}

export interface DashboardScanBridgeInput {
  status: ScanStatus;
  progress: number;
  modules: ModuleState[];
  findings: DefensiveFinding[];
  summary: ScanSummary | null;
  /** Joined target list, for the `asset` field on lifecycle events. */
  asset: string;
  error: string | null;
  /** True when heavy motion is disabled — drains the queue immediately. */
  reducedMotion: boolean;
  /**
   * The verdict the assessment reached, so the hero core settles on the SAME
   * numbers the Executive Summary and Encryption Score panels publish.
   *
   * The bridge used to derive its own: `summary.qScore` for the score (which
   * happens to agree) and `pqcReady / totalFindings` for post-quantum readiness
   * (which does not — that is a share of findings, while the platform's PQ
   * readiness is the published category score). The hero and the panel below it
   * could therefore print two different post-quantum percentages for one scan.
   */
  verdict: {
    score: number;
    postQuantumReadiness: number;
    gradeable: boolean;
    /**
     * Per-surface posture, projected from the assessment's published category
     * decomposition. Supplied rather than derived here for the same reason the
     * composite score is: the bridge used to run `scoreNodes(findings)` — a
     * severity mean over the finding list — which is a different model from the
     * one behind `score`, so the hero cards and the gauge they surround could
     * (and did) describe one scan with two incompatible verdicts.
     */
    nodeScores: Record<string, number>;
  } | null;
}

export function useDashboardScanBridge({
  status,
  progress,
  modules,
  findings,
  summary,
  asset,
  error,
  reducedMotion,
  verdict,
}: DashboardScanBridgeInput): void {
  const { state, dispatch } = useQve();

  const previousStatuses = React.useRef(new Map<string, ModuleState['status']>());
  const previousRun = React.useRef<ScanStatus>('idle');
  // Latest modules, read by the lifecycle effect without making it depend on
  // the array — it must fire on a run transition, not on every module update.
  const latestModules = React.useRef<ModuleState[]>(modules);
  latestModules.current = modules;
  const consumedFindings = React.useRef(0);
  const settled = React.useRef(false);
  const queue = React.useRef<ScanEvent[]>([]);
  const timer = React.useRef<number | null>(null);

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
    step();
  }, [dispatch]);

  const enqueue = React.useCallback(
    (events: ScanEvent[]) => {
      if (events.length === 0) return;
      if (reducedMotion) {
        for (const event of events) dispatch({ type: 'ingest', event });
        return;
      }
      queue.current.push(...events);
      pump();
    },
    [dispatch, pump, reducedMotion],
  );

  React.useEffect(
    () => () => {
      if (timer.current !== null) window.clearTimeout(timer.current);
      timer.current = null;
    },
    [],
  );

  /* ── Run lifecycle ─────────────────────────────────────────────────────── */
  React.useEffect(() => {
    const running = status === 'queued' || status === 'running' || status === 'analyzing';
    const wasRunning =
      previousRun.current === 'queued' || previousRun.current === 'running' || previousRun.current === 'analyzing';

    if (running && !wasRunning) {
      // A new run wipes the engine so the second scan cannot inherit the
      // first one's verdicts.
      queue.current = [];
      if (timer.current !== null) window.clearTimeout(timer.current);
      timer.current = null;
      previousStatuses.current.clear();
      consumedFindings.current = 0;
      settled.current = false;
      dispatch({
        type: 'ingest',
        event: {
          id: nextId('scan-start'),
          type: 'SCAN_STARTED',
          timestamp: Date.now(),
          category: 'scan',
          status: 'running',
          progress: 0,
          severity: 'info',
          finding: 'Authorized cryptographic inventory scan started',
          asset,
        },
      });
    }

    if (!running && wasRunning) {
      const failed = status === 'failed' || status === 'cancelled';

      /* Reconcile before closing the run. A module whose terminal frame never
         reached the client — a dropped SSE chunk, or a cancelled run — would
         otherwise leave its node card spinning indefinitely after the scan is
         demonstrably over.

         The backend closes its own ledger before every terminal frame, so this
         should now be empty on a healthy run. When it is not, the module is
         reported as FAILED with the reason, never as "not applicable": a module
         that was mid-flight when the stream died did not decline to run, and
         painting it the same grey as a genuine n/a is precisely the conflation
         that made a working scan read "Transport & Ciphers · SKIPPED". */
      const unresolved = latestModules.current
        .filter((module) => module.status === 'Running' || module.status === 'Queued')
        .map((module) => {
          previousStatuses.current.set(module.id, module.status);
          const reason = failed
            ? (status === 'cancelled' ? 'Scan cancelled before this module reported' : 'Scan failed before this module reported')
            : 'Scan stream ended before this module reported a result';
          return moduleEvent(
            { ...module, status: 'Failed', error: module.error ?? reason, reason: module.reason ?? reason },
            progress,
          );
        })
        .filter((event): event is ScanEvent => event !== null);

      enqueue([
        ...unresolved,
        {
          id: nextId(failed ? 'scan-error' : 'scan-complete'),
          type: failed ? 'ERROR' : 'SCAN_COMPLETED',
          timestamp: Date.now(),
          category: 'scan',
          status: failed ? 'failed' : 'pass',
          progress: failed ? progress : 100,
          severity: failed ? 'critical' : 'info',
          finding: failed
            ? (error ?? (status === 'cancelled' ? 'Scan cancelled by operator' : 'Scan failed'))
            : 'Authorized cryptographic inventory scan completed',
          asset,
        },
      ]);
    }

    previousRun.current = status;
  }, [status, progress, asset, error, dispatch, enqueue]);

  /* ── Module state transitions ──────────────────────────────────────────── */
  React.useEffect(() => {
    const events: ScanEvent[] = [];
    for (const module of modules) {
      const seen = previousStatuses.current.get(module.id);
      if (seen === module.status) continue;
      previousStatuses.current.set(module.id, module.status);
      if (module.status === 'Queued') continue;
      const event = moduleEvent(module, progress);
      if (event) events.push(event);
    }
    enqueue(events);
  }, [modules, progress, enqueue]);

  /* ── Findings ──────────────────────────────────────────────────────────── */
  React.useEffect(() => {
    if (findings.length < consumedFindings.current) consumedFindings.current = 0;
    if (findings.length === consumedFindings.current) return;
    const fresh = findings.slice(consumedFindings.current);
    consumedFindings.current = findings.length;
    // Only the material observations reach the visualization: routing every
    // SAFE row would bury the exposures the operator needs to see.
    enqueue(fresh.filter((finding) => finding.threatLevel !== 'SAFE').slice(0, 40).map((finding) => findingEvent(finding, progress)));
  }, [findings, progress, enqueue]);

  /* ── Settle: real scores, once ─────────────────────────────────────────── */
  React.useEffect(() => {
    if (!summary || settled.current) return;
    if (status === 'queued' || status === 'running' || status === 'analyzing') return;
    // The engine must have observed the run it is being asked to grade. Loading
    // a past scan into the Findings tab sets `status: 'completed'` and a summary
    // without ever streaming events — settling there would paint a grade onto a
    // core that is still showing Standby, which is a verdict the visualization
    // did not earn.
    if (state.run === 'idle') return;
    // An ungradeable run (a module ledger that never closed) gets no verdict —
    // the core keeps its live state rather than certifying a partial estate.
    if (verdict && !verdict.gradeable) return;
    settled.current = true;
    const score = Math.max(0, Math.min(100, Math.round(verdict ? verdict.score : summary.qScore)));
    const grade = scoreToGrade(score);
    const postQuantum = verdict
      ? Math.max(0, Math.min(100, Math.round(verdict.postQuantumReadiness)))
      : summary.totalFindings > 0
        ? Math.round((summary.pqcReady / summary.totalFindings) * 100)
        : 0;
    dispatch({
      type: 'settle',
      grade: grade.grade,
      gradeColor: grade.color,
      score,
      postQuantumScore: postQuantum,
      nodeScores: verdict?.nodeScores ?? {},
    });
  }, [summary, status, findings, state.run, dispatch, verdict]);
}
