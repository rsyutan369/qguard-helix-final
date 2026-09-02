'use client';

/**
 * Quantum Scan Theatre — the live scanning environment for Local and Dev modes.
 *
 * ONE component, both modes. Local runs its engines in a Web Worker and Dev runs
 * them on the server over SSE, but both produce the same `ScanEvent` stream, the
 * same `EngineRun` ledger and the same `ExposureFinding` shape — so the theatre
 * takes those and nothing mode-specific. Anything a mode alone can measure (the
 * byte volume of an authorised folder, the file count of a resolved repository)
 * arrives as the `volume` tile, supplied by the mode that can actually measure
 * it and omitted by the one that cannot.
 *
 * THE ACCURACY CONTRACT
 * ---------------------
 * Every number on this surface is emitted by the running scan:
 *
 *   progress   the orchestrator's own completion figure
 *   coverage   the scan's own files-analysed / files-discovered once settled;
 *              summed engine passes while live, LABELLED as passes because a
 *              file read by six engines is six passes and not six files
 *   engines    completed / selected, using the same predicate `computeCoverage`
 *              uses, with settled shown separately
 *   volume     measured by the mode, or absent
 *   elapsed    wall clock between the operator starting and the scan settling
 *   pulse      events actually received, bucketed per second
 *   severity   findings while live; CORRELATED EXPOSURES once they exist, which
 *              is the population the risk score is weighted over — the unit is
 *              printed on the panel either way
 *
 * There is no synthetic risk score here. While the scan runs the theatre
 * publishes the HIGHEST SEVERITY OBSERVED, which is a fact; the graded security
 * risk only appears once the assessment completes, and then it is the
 * assessment's own `scores.securityRisk` — never a second model computed here.
 * A rival score on a live panel is how two surfaces of one product come to
 * disagree about the same scan.
 *
 * Severity counts come from `reconcileExposure`, never from a local tally, so
 * this panel and the result panels below it cannot drift.
 */

import React from 'react';
import { AnimatePresence, motion, useReducedMotion } from 'motion/react';
import {
  Activity, Binary, ChevronRight, CircleSlash, Database, Eye, Gauge as GaugeIcon,
  Loader2, Radar, ShieldAlert, ShieldCheck, Square, Timer, X,
} from 'lucide-react';
import { cn } from '@/lib/utils';
import { ACCENT, Panel } from '@/components/quantum-scan/ui';
import { SEVERITY_COLOR, QUANTUM_COLOR, FindingDetail } from './shared';
import { ScanStage, type StageDetection, type StageToken } from './ScanStage';
import type { EngineHealthRow, KnowledgeBaseBadge } from './ScannerIntelligence';
import type { ScanTelemetryFrame, TelemetryLevel } from '@/lib/scanner/exposure/telemetry-frame';
import { reconcileExposure } from '@/lib/scanner/exposure/exposure-truth';
import {
  SEVERITY_ORDER,
  type EngineRun,
  type ExposureAssessment,
  type ExposureFinding,
  type FindingSeverity,
  type ScanMode,
} from '@/lib/scanner/exposure/types';

/* ──────────────────────────────────────────────────────────────── contract ── */

export type TheatreStatus = 'starting' | 'scanning' | 'complete' | 'cancelled' | 'error';

export interface ScanTheatreProps {
  mode: Extract<ScanMode, 'local' | 'dev'>;
  status: TheatreStatus;
  /** Real 0-100 from the orchestrator. */
  progress: number;
  runs: EngineRun[];
  findings: ExposureFinding[];
  telemetry: ScanTelemetryFrame[];
  currentStep: string | null;
  startedAt: number | null;
  /** True while the worker / EventSource is attached. */
  streamOpen: boolean;
  target: { label: string; detail?: string | null };
  /**
   * Corpus volume, measured by the mode. Local knows the authorised byte count
   * before the scan starts; Dev learns the file count once the repository
   * resolves. A mode that cannot measure it passes null and the tile says so.
   */
  volume?: { label: string; value: string; sublabel: string } | null;
  /** Present once the scan settles. The ONLY source of a graded risk score. */
  assessment: ExposureAssessment | null;
  knowledgeBase: KnowledgeBaseBadge | null;
  engineHealth: EngineHealthRow[];
  error?: string | null;
  onCancel?: () => void;
  /** Scrolls the operator to the full result panels below. */
  onViewAll?: () => void;
  onDismiss?: () => void;
}

/* ─────────────────────────────────────────────────────────────── formatting ── */

const SEVERITIES: FindingSeverity[] = ['critical', 'high', 'medium', 'low', 'info'];

const LEVEL_STYLE: Record<TelemetryLevel, { tag: string; color: string }> = {
  info: { tag: 'INFO', color: '#7dd3fc' },
  ok: { tag: ' OK ', color: ACCENT.emerald },
  warn: { tag: 'WARN', color: ACCENT.amber },
  error: { tag: 'FAIL', color: ACCENT.rose },
  detect: { tag: 'HIT ', color: ACCENT.violet },
};

const BAND_COLOR: Record<string, string> = {
  critical: ACCENT.rose,
  high: '#fb923c',
  moderate: ACCENT.amber,
  low: ACCENT.blue,
  minimal: ACCENT.emerald,
};

function clockOf(iso: string): string {
  const date = new Date(iso);
  if (Number.isNaN(date.getTime())) return '--:--:--';
  return date.toTimeString().slice(0, 8);
}

function formatDuration(ms: number): string {
  const total = Math.max(0, Math.floor(ms / 1000));
  const hours = Math.floor(total / 3600);
  const minutes = Math.floor((total % 3600) / 60);
  const seconds = total % 60;
  return `${String(hours).padStart(2, '0')}:${String(minutes).padStart(2, '0')}:${String(seconds).padStart(2, '0')}`;
}

export function formatBytes(bytes: number): string {
  if (!Number.isFinite(bytes) || bytes <= 0) return '0 B';
  const units = ['B', 'KB', 'MB', 'GB', 'TB'];
  const index = Math.min(units.length - 1, Math.floor(Math.log(bytes) / Math.log(1024)));
  const value = bytes / 1024 ** index;
  return `${value >= 100 || index === 0 ? Math.round(value) : value.toFixed(1)} ${units[index]}`;
}

/** Keeps the last two path segments — enough to identify, short enough to read. */
function shortPath(path: string): string {
  const parts = path.split(/[\\/]/).filter(Boolean);
  return parts.length <= 2 ? path : `…/${parts.slice(-2).join('/')}`;
}

/* ─────────────────────────────────────────────────────── live derived state ── */

/**
 * A one-second heartbeat that exists only while the scan is live.
 *
 * It drives the elapsed clock and the event-pulse histogram. Both are real
 * measurements of the stream: the histogram counts telemetry frames that
 * actually arrived in each second, so an idle second reads as an idle second
 * rather than as a comforting animation.
 */
function useScanPulse(telemetryLength: number, running: boolean) {
  const [tick, setTick] = React.useState(0);
  const [pulse, setPulse] = React.useState<number[]>(() => new Array(14).fill(0));
  const lastLength = React.useRef(telemetryLength);
  const currentLength = React.useRef(telemetryLength);
  currentLength.current = telemetryLength;

  React.useEffect(() => {
    if (!running) return;
    /* Resync on start: a new scan resets the console to zero, and a bucket must
       never report the difference between two different runs. */
    lastLength.current = currentLength.current;
    const timer = window.setInterval(() => {
      const received = Math.max(0, currentLength.current - lastLength.current);
      lastLength.current = currentLength.current;
      setPulse((current) => [...current.slice(1), received]);
      setTick((current) => current + 1);
    }, 1000);
    return () => window.clearInterval(timer);
  }, [running]);

  return { tick, pulse };
}

/* ─────────────────────────────────────────────────────────────── the panel ─── */

export function ScanTheatre({
  mode,
  status,
  progress,
  runs,
  findings,
  telemetry,
  currentStep,
  startedAt,
  streamOpen,
  target,
  volume,
  assessment,
  knowledgeBase,
  engineHealth,
  error,
  onCancel,
  onViewAll,
  onDismiss,
}: ScanTheatreProps) {
  const reduceMotion = useReducedMotion();
  const running = status === 'scanning' || status === 'starting';
  const [selected, setSelected] = React.useState<ExposureFinding | null>(null);
  const { tick, pulse } = useScanPulse(telemetry.length, running);

  /* ── elapsed: real, and frozen the moment the scan settles ──────────── */
  const settledAt = React.useRef<number | null>(null);
  if (running) settledAt.current = null;
  else if (settledAt.current === null && startedAt !== null) {
    const completed = assessment?.task.completedAt ? Date.parse(assessment.task.completedAt) : NaN;
    settledAt.current = Number.isNaN(completed) ? Date.now() : completed;
  }
  const elapsedMs = startedAt === null ? 0 : (running ? Date.now() : settledAt.current ?? Date.now()) - startedAt;

  /* ── ledger arithmetic ──────────────────────────────────────────────── */
  const enginesSettled = runs.filter(
    (run) => run.state !== 'pending' && run.state !== 'running',
  ).length;
  const enginesRunning = runs.filter((run) => run.state === 'running');
  /* The same predicate `computeCoverage` uses, so the tile and the basis line
     below it cannot disagree about what "completed" means. */
  const enginesCompleted = runs.filter((run) => run.state === 'completed').length;

  /**
   * Coverage, with the honest unit.
   *
   * Once the assessment settles, the canonical figure is the scan's own
   * `coverage.filesAnalyzed / filesDiscovered` — distinct files, counted once.
   *
   * While the scan is live that figure does not exist yet, so the tile falls
   * back to summed engine units. Those are NOT files: a file read by six
   * engines contributes six passes, so the same corpus that reports "126 of
   * 341 files" here summed to "477 of 479". The ratio is a fair progress
   * measure, the absolute numbers are engine passes, and the label now says so
   * rather than calling them files.
   */
  const coverage = React.useMemo(() => {
    const settled = assessment?.task.coverage;
    if (settled && settled.filesDiscovered > 0) {
      return {
        done: settled.filesAnalyzed,
        total: settled.filesDiscovered,
        unit: 'files analysed / discovered',
        canonical: true,
      };
    }
    let done = 0;
    let total = 0;
    for (const run of runs) {
      if (!run.units || run.units.total <= 0) continue;
      done += Math.min(run.units.done, run.units.total);
      total += run.units.total;
    }
    return { done, total, unit: 'engine passes · summed', canonical: false };
  }, [runs, assessment]);

  /**
   * Severity, in the unit that matches what is shown beside it.
   *
   * While the scan runs there are only findings — correlation happens at the
   * end — so the donut counts findings and says so. Once the assessment
   * settles the panel switches to the reconciler's EXPOSURE tally, because
   * that is the population the security score beside it is weighted over.
   * Counting one population and scoring another is what made "1 critical" sit
   * next to "99/100" and read as a defect.
   */
  const truth = React.useMemo(
    () => (assessment ? reconcileExposure(assessment) : null),
    [assessment],
  );

  const severity = React.useMemo(() => {
    if (truth) {
      return { counts: truth.exposureSeverity, total: assessment!.exposures.length, unit: 'exposures' as const };
    }
    const counts: Record<FindingSeverity, number> = { critical: 0, high: 0, medium: 0, low: 0, info: 0 };
    for (const finding of findings) counts[finding.severity] += 1;
    return { counts, total: findings.length, unit: 'findings' as const };
  }, [truth, assessment, findings]);

  const topSeverity = React.useMemo(() => {
    let top: FindingSeverity | null = null;
    for (const value of SEVERITIES) {
      if (severity.counts[value] > 0) {
        top = value;
        break;
      }
    }
    return top;
  }, [severity]);

  /* ── discovery timeline: real receipt times, one entry per finding ───── */
  const discoveryTimes = React.useRef<number[]>([]);
  const knownFindings = React.useRef(0);
  if (findings.length < knownFindings.current) {
    discoveryTimes.current = [];
    knownFindings.current = 0;
  }
  if (findings.length > knownFindings.current) {
    const now = Date.now();
    for (let index = knownFindings.current; index < findings.length; index += 1) {
      discoveryTimes.current.push(now);
    }
    knownFindings.current = findings.length;
  }

  const discoverySeries = React.useMemo(() => {
    const times = discoveryTimes.current;
    if (!startedAt || times.length === 0) return new Array(24).fill(0) as number[];
    const span = Math.max(1000, (settledAt.current ?? Date.now()) - startedAt);
    const buckets = new Array(24).fill(0) as number[];
    for (const at of times) {
      const index = Math.min(23, Math.max(0, Math.floor(((at - startedAt) / span) * 24)));
      buckets[index] += 1;
    }
    return buckets;
    // `tick` keeps the series moving while the scan is live.
  }, [findings.length, startedAt, tick]);

  /* ── progress at discovery, so a marker sits where it was found ─────── */
  const markerProgress = React.useRef(new Map<string, number>());
  for (const finding of findings) {
    if (!markerProgress.current.has(finding.id)) markerProgress.current.set(finding.id, progress);
  }

  const detections: StageDetection[] = React.useMemo(
    () =>
      findings.slice(-24).map((finding) => ({
        id: finding.id,
        severity: finding.severity,
        color: SEVERITY_COLOR[finding.severity],
        title: finding.title,
        detail:
          finding.evidence[0]?.file
            ? shortPath(finding.evidence[0].file)
            : finding.canonicalAlgorithm ?? finding.algorithm ?? finding.category,
        atProgress: markerProgress.current.get(finding.id) ?? progress,
      })),
    [findings, progress],
  );

  /* ── stage tokens: real observed cryptography and real artefacts ────── */
  const tokens: StageToken[] = React.useMemo(() => {
    const seen = new Map<string, string>();
    for (const finding of findings.slice(-80)) {
      const algorithm = finding.canonicalAlgorithm ?? finding.algorithm;
      if (algorithm) seen.set(algorithm, QUANTUM_COLOR[finding.quantumStatus]);
      if (finding.protocol) seen.set(finding.protocol, QUANTUM_COLOR[finding.quantumStatus]);
    }
    for (const frame of telemetry.slice(-50)) {
      if (frame.artifact && seen.size < 40) seen.set(shortPath(frame.artifact), 'rgba(148,163,184,0.85)');
    }
    return [...seen.entries()].slice(-30).map(([text, color]) => ({ text, color }));
  }, [findings, telemetry]);

  /* ── the artefact under the glass ───────────────────────────────────── */
  const focus = React.useMemo(() => {
    for (let index = telemetry.length - 1; index >= 0; index -= 1) {
      if (telemetry[index].artifact) return telemetry[index].artifact ?? null;
    }
    return null;
  }, [telemetry]);

  const engineLabel = enginesRunning[0]?.label ?? (currentStep ? currentStep.split(':')[0] : null);

  const caption =
    status === 'starting' ? 'INITIALISING'
      : status === 'scanning' ? 'SCANNING'
        : status === 'cancelled' ? 'CANCELLED'
          : status === 'error' ? 'HALTED'
            : 'SCAN COMPLETE';

  /* ── graded risk: the assessment's own number, or nothing ───────────── */
  const scores = assessment?.task.scores ?? null;
  const graded = scores && scores.securityRisk !== null && scores.securityBand !== null;

  /* ── engine health, as reported ─────────────────────────────────────── */
  const health = React.useMemo(() => {
    if (engineHealth.length === 0) return { label: 'UNREPORTED', color: ACCENT.slate };
    const unhealthy = engineHealth.filter((entry) => entry.health !== 'healthy').length;
    if (unhealthy === 0) return { label: 'OPERATIONAL', color: ACCENT.emerald };
    return { label: `DEGRADED · ${unhealthy}`, color: ACCENT.amber };
  }, [engineHealth]);

  const lastFrame = telemetry[telemetry.length - 1];

  return (
    <>
      <Panel
        glow={running}
        className="overflow-hidden"
        aria-label="Live quantum vulnerability scan"
      >
        {/* ── control bar ─────────────────────────────────────────────── */}
        <div className="flex flex-wrap items-center gap-3 border-b border-white/[0.07] bg-white/[0.015] px-4 py-3">
          <span
            className="grid h-8 w-8 shrink-0 place-items-center rounded-lg border border-cyan-400/25 bg-cyan-400/[0.08] text-cyan-300"
            aria-hidden
          >
            <Radar className={cn('h-4 w-4', running && !reduceMotion && 'animate-pulse')} />
          </span>

          <div className="min-w-0 flex-1">
            <p className="font-mono text-[9.5px] font-bold uppercase tracking-[0.2em] text-slate-500">
              {mode === 'local' ? 'Local target' : 'Dev target'}
            </p>
            <p className="truncate text-[13.5px] font-black text-white">{target.label}</p>
          </div>

          {target.detail && (
            <span className="hidden shrink-0 rounded-md border border-white/[0.08] px-2 py-1 font-mono text-[10px] text-slate-400 sm:inline">
              {target.detail}
            </span>
          )}

          {running ? (
            <button
              type="button"
              onClick={onCancel}
              className="inline-flex shrink-0 items-center gap-1.5 rounded-lg border border-rose-400/35 bg-rose-500/[0.1] px-3 py-2 text-[12px] font-black uppercase tracking-[0.12em] text-rose-200 transition-colors hover:bg-rose-500/20"
            >
              <Square className="h-3 w-3 fill-current" /> Stop scan
            </button>
          ) : (
            <span
              className="inline-flex shrink-0 items-center gap-1.5 rounded-lg border px-3 py-2 font-mono text-[11px] font-black uppercase tracking-[0.12em]"
              style={{
                borderColor: `${status === 'complete' ? ACCENT.emerald : status === 'error' ? ACCENT.rose : ACCENT.amber}55`,
                color: status === 'complete' ? ACCENT.emerald : status === 'error' ? ACCENT.rose : ACCENT.amber,
              }}
            >
              {status === 'complete' ? <ShieldCheck className="h-3.5 w-3.5" /> : status === 'error' ? <ShieldAlert className="h-3.5 w-3.5" /> : <CircleSlash className="h-3.5 w-3.5" />}
              {caption}
            </span>
          )}

          {onDismiss && !running && (
            <button
              type="button"
              onClick={onDismiss}
              className="shrink-0 rounded-lg border border-white/[0.08] p-2 text-slate-400 transition-colors hover:text-white"
              aria-label="Hide the scan visualisation"
            >
              <X className="h-3.5 w-3.5" />
            </button>
          )}
        </div>

        {/* ── stage ───────────────────────────────────────────────────── */}
        <ScanStage
          running={running}
          progress={progress}
          focus={focus}
          engineLabel={engineLabel}
          caption={caption}
          tokens={tokens}
          detections={detections}
          onSelectDetection={(id) => setSelected(findings.find((finding) => finding.id === id) ?? null)}
          className="h-[280px] w-full border-b border-white/[0.07] sm:h-[340px]"
        />

        {/* ── metric strip ────────────────────────────────────────────── */}
        <div className="grid grid-cols-2 gap-px border-b border-white/[0.07] bg-white/[0.05] sm:grid-cols-3 xl:grid-cols-6">
          <MetricTile label="Scan progress" sublabel={running ? 'live' : 'final'}>
            <div className="flex items-baseline gap-2">
              <span className="font-mono text-[20px] font-black tabular-nums text-white">{Math.round(progress)}%</span>
            </div>
            <SegmentBar value={progress} />
          </MetricTile>

          <MetricTile
            label="Coverage"
            sublabel={coverage.total > 0 ? coverage.unit : 'not reported'}
          >
            {coverage.total > 0 ? (
              <p className="font-mono text-[17px] font-black tabular-nums text-white">
                {coverage.done.toLocaleString()}
                <span className="text-slate-500"> / {coverage.total.toLocaleString()}</span>
              </p>
            ) : (
              <NotMeasured>No engine reported unit counts</NotMeasured>
            )}
          </MetricTile>

          {/* "Completed", not "settled". Coverage scores engines that reached
              `completed`; a not-applicable or failed engine is settled but did
              NOT report, and showing 13/13 beside a basis line reading "8 of 13
              engines completed" made one scan look like two. */}
          <MetricTile label="Engines" sublabel={`${enginesSettled} settled · ${runs.length} selected`}>
            <p className="font-mono text-[17px] font-black tabular-nums text-white">
              {enginesCompleted}
              <span className="text-slate-500"> / {runs.length}</span>
            </p>
            {enginesRunning.length > 0 ? (
              <p className="truncate font-mono text-[10px] text-cyan-300">{enginesRunning[0].label}</p>
            ) : (
              <p className="font-mono text-[10px] text-slate-600">completed</p>
            )}
          </MetricTile>

          <MetricTile label={volume?.label ?? 'Corpus'} sublabel={volume?.sublabel ?? 'not measured'}>
            {volume ? (
              <p className="font-mono text-[17px] font-black tabular-nums text-white">{volume.value}</p>
            ) : (
              <NotMeasured>This mode does not measure corpus volume</NotMeasured>
            )}
          </MetricTile>

          <MetricTile label="Elapsed" sublabel={running ? 'running' : 'total'}>
            <p className="font-mono text-[17px] font-black tabular-nums text-white">{formatDuration(elapsedMs)}</p>
          </MetricTile>

          <MetricTile label="Event pulse" sublabel="events / second">
            <PulseBars values={pulse} active={running} />
          </MetricTile>
        </div>

        {/* ── three consoles ──────────────────────────────────────────── */}
        <div className="grid grid-cols-[minmax(0,1fr)] gap-px bg-white/[0.05] lg:grid-cols-3">
          <TelemetryConsole frames={telemetry} running={running} />
          <ExposureOverview
            counts={severity.counts}
            total={severity.total}
            unit={severity.unit}
            topSeverity={topSeverity}
            graded={graded ? { score: scores!.securityRisk!, band: scores!.securityBand! } : null}
            correlationNote={truth?.scoreUnitNote ?? null}
            series={discoverySeries}
          />
          <FindingsConsole
            findings={findings}
            onSelect={setSelected}
            onViewAll={onViewAll}
          />
        </div>

        {/* ── error ───────────────────────────────────────────────────── */}
        {error && (
          <div className="flex items-start gap-2.5 border-t border-rose-400/20 bg-rose-500/[0.06] px-4 py-3">
            <ShieldAlert className="mt-0.5 h-4 w-4 shrink-0 text-rose-400" />
            <p className="text-[12.5px] leading-relaxed text-rose-100/85">{error}</p>
          </div>
        )}

        {/* ── status bar ──────────────────────────────────────────────── */}
        <div className="flex flex-wrap items-center gap-x-6 gap-y-1.5 border-t border-white/[0.07] bg-[#050914]/80 px-4 py-2.5">
          <StatusItem icon={GaugeIcon} label="Engine status">
            <span style={{ color: health.color }}>{health.label}</span>
          </StatusItem>
          <StatusItem icon={Database} label="Catalog">
            {knowledgeBase?.version ?? 'unreported'}
          </StatusItem>
          <StatusItem icon={Binary} label="Detection rules">
            {knowledgeBase ? knowledgeBase.rules.toLocaleString() : 'unreported'}
          </StatusItem>
          <StatusItem icon={Activity} label="Algorithms">
            {knowledgeBase ? knowledgeBase.algorithms.toLocaleString() : 'unreported'}
          </StatusItem>
          <StatusItem icon={Timer} label="Last event">
            {lastFrame ? clockOf(lastFrame.at) : '--:--:--'}
          </StatusItem>
          <StatusItem icon={Radar} label="Stream">
            <span
              className="inline-flex items-center gap-1.5"
              style={{ color: streamOpen ? ACCENT.emerald : ACCENT.slate }}
            >
              <span
                aria-hidden
                className={cn('h-1.5 w-1.5 rounded-full', streamOpen && !reduceMotion && 'animate-pulse')}
                style={{ backgroundColor: streamOpen ? ACCENT.emerald : ACCENT.slate }}
              />
              {streamOpen ? (mode === 'local' ? 'WORKER LIVE' : 'SSE LIVE') : 'CLOSED'}
            </span>
          </StatusItem>
        </div>
      </Panel>

      <FindingDetail
        finding={selected}
        onClose={() => setSelected(null)}
        exposures={assessment?.exposures}
      />
    </>
  );
}

/* ─────────────────────────────────────────────────────────────────── atoms ─── */

function MetricTile({
  label,
  sublabel,
  children,
}: {
  label: string;
  sublabel?: string;
  children: React.ReactNode;
}) {
  return (
    <div className="min-w-0 bg-[#080d1a] px-4 py-3">
      <p className="font-mono text-[9px] font-bold uppercase tracking-[0.18em] text-slate-500">{label}</p>
      <div className="mt-1.5 space-y-1">{children}</div>
      {sublabel && (
        <p className="mt-1 font-mono text-[9px] uppercase tracking-[0.14em] text-slate-600">{sublabel}</p>
      )}
    </div>
  );
}

function NotMeasured({ children }: { children: React.ReactNode }) {
  return (
    <p className="font-mono text-[11px] leading-snug text-slate-500">
      <span className="text-slate-400">Not measured</span>
      <span className="block text-[9.5px] text-slate-600">{children}</span>
    </p>
  );
}

/** 28 segments, filled from the orchestrator's real progress. */
function SegmentBar({ value }: { value: number }) {
  const SEGMENTS = 28;
  const filled = Math.round((Math.max(0, Math.min(100, value)) / 100) * SEGMENTS);
  return (
    <div className="flex gap-[2px]" aria-hidden>
      {Array.from({ length: SEGMENTS }, (_, index) => (
        <span
          key={index}
          className="h-2.5 flex-1 rounded-[1px]"
          style={{
            backgroundColor: index < filled ? ACCENT.cyan : 'rgba(148,163,184,0.14)',
            boxShadow: index === filled - 1 ? `0 0 8px ${ACCENT.cyan}` : undefined,
          }}
        />
      ))}
    </div>
  );
}

/** Real events per second over the last 14 seconds. An idle second is empty. */
function PulseBars({ values, active }: { values: number[]; active: boolean }) {
  const peak = Math.max(1, ...values);
  const latest = values[values.length - 1] ?? 0;
  return (
    <div className="space-y-1">
      <p className="font-mono text-[17px] font-black tabular-nums text-white">{latest}</p>
      <div className="flex h-6 items-end gap-[2px]" aria-hidden>
        {values.map((value, index) => (
          <span
            key={index}
            className="flex-1 rounded-[1px] transition-[height] duration-500"
            style={{
              height: `${Math.max(6, (value / peak) * 100)}%`,
              backgroundColor: value === 0 ? 'rgba(148,163,184,0.16)' : active ? ACCENT.cyan : ACCENT.slate,
              opacity: 0.45 + (index / values.length) * 0.55,
            }}
          />
        ))}
      </div>
    </div>
  );
}

function StatusItem({
  icon: Icon,
  label,
  children,
}: {
  icon: typeof Activity;
  label: string;
  children: React.ReactNode;
}) {
  return (
    <span className="inline-flex items-center gap-1.5 font-mono text-[10px] uppercase tracking-[0.14em]">
      <Icon aria-hidden className="h-3 w-3 text-slate-600" />
      <span className="text-slate-600">{label}:</span>
      <span className="font-bold text-slate-300">{children}</span>
    </span>
  );
}

/* ──────────────────────────────────────────────────────── telemetry console ── */

function TelemetryConsole({ frames, running }: { frames: ScanTelemetryFrame[]; running: boolean }) {
  const scrollRef = React.useRef<HTMLDivElement | null>(null);
  const pinned = React.useRef(true);

  React.useEffect(() => {
    const node = scrollRef.current;
    if (!node || !pinned.current) return;
    node.scrollTop = node.scrollHeight;
  }, [frames.length]);

  return (
    <section className="min-w-0 bg-[#080d1a]" aria-label="Scan telemetry">
      <header className="flex items-center justify-between gap-2 border-b border-white/[0.06] px-4 py-2.5">
        <h3 className="font-mono text-[10px] font-bold uppercase tracking-[0.2em] text-slate-400">Scan telemetry</h3>
        <span className="inline-flex items-center gap-1.5 font-mono text-[9.5px] font-bold uppercase tracking-[0.16em] text-emerald-300">
          <span
            aria-hidden
            className={cn('h-1.5 w-1.5 rounded-full bg-emerald-400', running && 'animate-pulse motion-reduce:animate-none')}
          />
          {running ? 'Live feed' : 'Feed closed'}
        </span>
      </header>

      <div
        ref={scrollRef}
        onScroll={(event) => {
          const node = event.currentTarget;
          pinned.current = node.scrollHeight - node.scrollTop - node.clientHeight < 32;
        }}
        className="h-[15.5rem] overflow-y-auto px-4 py-2.5"
      >
        {frames.length === 0 ? (
          <p className="pt-8 text-center font-mono text-[11px] text-slate-600">
            Waiting for the first engine event.
          </p>
        ) : (
          <ol className="space-y-[3px]">
            {frames.map((frame) => {
              const style = LEVEL_STYLE[frame.level];
              const color = frame.level === 'detect' && frame.severity ? SEVERITY_COLOR[frame.severity] : style.color;
              return (
                <li key={frame.seq} className="flex gap-2 font-mono text-[10.5px] leading-relaxed">
                  <span className="shrink-0 text-slate-600">{clockOf(frame.at)}</span>
                  <span className="shrink-0 font-bold" style={{ color }}>
                    [{style.tag}]
                  </span>
                  <span className="min-w-0 flex-1 break-words text-slate-300">
                    {frame.text}
                    {frame.units && frame.units.total > 0 && (
                      <span className="text-slate-600">
                        {' '}
                        ({frame.units.done}/{frame.units.total} {frame.units.unit})
                      </span>
                    )}
                  </span>
                </li>
              );
            })}
          </ol>
        )}
      </div>
    </section>
  );
}

/* ───────────────────────────────────────────────────────── exposure overview ── */

function ExposureOverview({
  counts,
  total,
  unit,
  topSeverity,
  graded,
  correlationNote,
  series,
}: {
  counts: Record<FindingSeverity, number>;
  total: number;
  /** Which population these counts describe. Rendered, never assumed. */
  unit: 'findings' | 'exposures';
  topSeverity: FindingSeverity | null;
  graded: { score: number; band: string } | null;
  correlationNote: string | null;
  series: number[];
}) {
  const RADIUS = 52;
  const STROKE = 13;
  const circumference = 2 * Math.PI * RADIUS;
  let offset = 0;

  const arcs = SEVERITIES.filter((severity) => counts[severity] > 0).map((severity) => {
    const fraction = counts[severity] / Math.max(1, total);
    const arc = {
      severity,
      dash: fraction * circumference,
      offset,
    };
    offset += fraction * circumference;
    return arc;
  });

  const peak = Math.max(1, ...series);

  return (
    <section className="min-w-0 bg-[#080d1a]" aria-label="Exposure overview">
      <header className="flex items-center justify-between gap-2 border-b border-white/[0.06] px-4 py-2.5">
        <h3 className="font-mono text-[10px] font-bold uppercase tracking-[0.2em] text-slate-400">Exposure overview</h3>
        {/* The unit the donut is counting. It changes when the scan settles —
            findings while live, correlated exposures once they exist — and the
            score below is weighted over exposures either way. */}
        <span
          className="font-mono text-[9px] font-bold uppercase tracking-[0.16em] text-slate-500"
          title={
            unit === 'exposures'
              ? 'Correlated exposures: findings that are one underlying issue, counted once. This is the population the risk score is weighted over.'
              : 'Raw findings. Correlation into exposures happens when the scan completes.'
          }
        >
          {unit}
        </span>
      </header>

      <div className="flex h-[15.5rem] flex-col justify-between px-4 py-3">
        <div className="flex items-center gap-4">
          <div className="relative shrink-0">
            <svg width={132} height={132} viewBox="0 0 132 132" role="img" aria-label={`${total} ${unit} by severity`}>
              <circle cx={66} cy={66} r={RADIUS} fill="none" stroke="rgba(148,163,184,0.12)" strokeWidth={STROKE} />
              {arcs.map((arc) => (
                <circle
                  key={arc.severity}
                  cx={66}
                  cy={66}
                  r={RADIUS}
                  fill="none"
                  stroke={SEVERITY_COLOR[arc.severity]}
                  strokeWidth={STROKE}
                  strokeDasharray={`${arc.dash} ${circumference - arc.dash}`}
                  strokeDashoffset={-arc.offset}
                  transform="rotate(-90 66 66)"
                  strokeLinecap="butt"
                />
              ))}
            </svg>
            <div className="pointer-events-none absolute inset-0 flex flex-col items-center justify-center gap-0.5">
              <span className="font-mono text-[26px] font-black leading-none tabular-nums text-white">{total}</span>
              <span className="font-mono text-[8.5px] font-bold uppercase tracking-[0.16em] text-slate-500">
                {unit}
              </span>
            </div>
          </div>

          <ul className="min-w-0 flex-1 space-y-[3px]">
            {SEVERITIES.map((severity) => (
              <li key={severity} className="flex items-center gap-2">
                <span
                  aria-hidden
                  className="h-2 w-2 shrink-0 rounded-[2px]"
                  style={{ backgroundColor: SEVERITY_COLOR[severity] }}
                />
                <span className="w-8 shrink-0 text-right font-mono text-[13px] font-black tabular-nums text-white">
                  {counts[severity]}
                </span>
                <span
                  className="truncate font-mono text-[10px] font-bold uppercase tracking-[0.14em]"
                  style={{ color: SEVERITY_COLOR[severity] }}
                >
                  {severity}
                </span>
              </li>
            ))}
          </ul>
        </div>

        {/* Graded risk appears only when the assessment has produced one. */}
        <div className="flex items-end justify-between gap-3 border-t border-white/[0.06] pt-2.5">
          <div className="min-w-0">
            <p className="font-mono text-[9px] font-bold uppercase tracking-[0.16em] text-slate-500">
              {graded ? 'Security risk' : 'Highest severity observed'}
            </p>
            {graded ? (
              <p
                className="font-mono text-[15px] font-black uppercase tracking-[0.1em]"
                style={{ color: BAND_COLOR[graded.band] ?? ACCENT.slate }}
              >
                {graded.band} · {Math.round(graded.score)}
              </p>
            ) : (
              <p
                className="font-mono text-[15px] font-black uppercase tracking-[0.1em]"
                style={{ color: topSeverity ? SEVERITY_COLOR[topSeverity] : ACCENT.slate }}
              >
                {topSeverity ?? 'None yet'}
              </p>
            )}
            {!graded ? (
              <p className="mt-0.5 text-[9.5px] leading-tight text-slate-600">
                Graded on completion
              </p>
            ) : (
              <p
                className="mt-0.5 cursor-help text-[9.5px] leading-tight text-slate-600"
                title={correlationNote ?? undefined}
              >
                weighted over {total} {unit}
              </p>
            )}
          </div>

          <div className="flex h-9 w-28 shrink-0 items-end gap-[2px]" aria-label="Findings discovered over the scan">
            {series.map((value, index) => (
              <span
                key={index}
                className="flex-1 rounded-[1px]"
                style={{
                  height: `${Math.max(8, (value / peak) * 100)}%`,
                  backgroundColor: value === 0 ? 'rgba(148,163,184,0.14)' : ACCENT.violet,
                }}
              />
            ))}
          </div>
        </div>
      </div>
    </section>
  );
}

/* ────────────────────────────────────────────────────────── findings console ── */

function FindingsConsole({
  findings,
  onSelect,
  onViewAll,
}: {
  findings: ExposureFinding[];
  onSelect: (finding: ExposureFinding) => void;
  onViewAll?: () => void;
}) {
  const VISIBLE = 6;
  const recent = React.useMemo(() => [...findings].reverse(), [findings]);
  const shown = recent.slice(0, VISIBLE);
  const remaining = recent.length - shown.length;

  return (
    <section className="min-w-0 bg-[#080d1a]" aria-label="Live findings">
      <header className="flex items-center justify-between gap-2 border-b border-white/[0.06] px-4 py-2.5">
        <h3 className="font-mono text-[10px] font-bold uppercase tracking-[0.2em] text-slate-400">Live findings</h3>
        {onViewAll && findings.length > 0 && (
          <button
            type="button"
            onClick={onViewAll}
            className="font-mono text-[9.5px] font-bold uppercase tracking-[0.16em] text-cyan-300 transition-colors hover:text-cyan-200"
          >
            View all
          </button>
        )}
      </header>

      <div className="flex h-[15.5rem] flex-col justify-between px-2 py-2">
        {shown.length === 0 ? (
          <p className="pt-8 text-center font-mono text-[11px] leading-relaxed text-slate-600">
            No finding yet.
            <span className="mt-1 block text-slate-700">Findings appear the moment an engine reports one.</span>
          </p>
        ) : (
          <ul className="space-y-px">
            <AnimatePresence initial={false}>
              {shown.map((finding) => (
                <motion.li
                  key={finding.id}
                  initial={{ opacity: 0, x: 10 }}
                  animate={{ opacity: 1, x: 0 }}
                  exit={{ opacity: 0 }}
                  transition={{ duration: 0.24 }}
                >
                  <button
                    type="button"
                    onClick={() => onSelect(finding)}
                    className="group flex w-full items-center gap-2 rounded-lg px-2 py-[7px] text-left transition-colors hover:bg-white/[0.04] focus:outline-none focus-visible:ring-1 focus-visible:ring-cyan-400/60"
                  >
                    <span
                      className="w-[52px] shrink-0 rounded px-1 py-0.5 text-center font-mono text-[8.5px] font-black uppercase tracking-[0.08em]"
                      style={{
                        backgroundColor: `${SEVERITY_COLOR[finding.severity]}1f`,
                        color: SEVERITY_COLOR[finding.severity],
                      }}
                    >
                      {finding.severity}
                    </span>
                    <span className="min-w-0 flex-1">
                      <span className="block truncate text-[12px] font-bold text-slate-200">{finding.title}</span>
                      <span className="block truncate font-mono text-[9.5px] text-slate-500">
                        {finding.evidence[0]?.file
                          ? shortPath(finding.evidence[0].file)
                          : finding.evidence[0]?.scope ?? finding.engineId}
                      </span>
                    </span>
                    <ChevronRight
                      aria-hidden
                      className="h-3.5 w-3.5 shrink-0 text-slate-600 transition-colors group-hover:text-cyan-300"
                    />
                  </button>
                </motion.li>
              ))}
            </AnimatePresence>
          </ul>
        )}

        {remaining > 0 && (
          <p className="px-2 pt-1.5 font-mono text-[10px] text-slate-600">
            and {remaining.toLocaleString()} more finding{remaining === 1 ? '' : 's'} in the explorer below
          </p>
        )}
      </div>
    </section>
  );
}

/* ─────────────────────────────────────────────────────────────── entry gate ── */

/**
 * Placeholder shown while a scan is queueing but before the first event lands,
 * so the theatre never appears as an empty black box.
 */
export function ScanTheatreBoot({ label }: { label: string }) {
  return (
    <Panel className="flex items-center gap-3 px-5 py-5">
      <Loader2 className="h-4 w-4 animate-spin text-cyan-300" />
      <p className="text-[13px] font-bold text-slate-300">{label}</p>
      <Eye aria-hidden className="ml-auto h-4 w-4 text-slate-700" />
    </Panel>
  );
}
