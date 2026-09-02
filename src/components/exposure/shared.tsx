'use client';

/**
 * Shared Exposure Assessment UI (§34, §41, §50, §51, §52, §68, §69, §70).
 *
 * These components are mode-agnostic on purpose: a Local scan and a Dev scan
 * produce the same `ExposureAssessment`, so they render through the same
 * panels. That is what makes the two modes comparable rather than two
 * dashboards that happen to sit behind the same tabs.
 *
 * Three presentation rules run through all of it, each from the specification:
 *
 *  §37 severity and confidence are ALWAYS shown together and never merged.
 *  §41 coverage limitations are shown next to the numbers they qualify, not in
 *      a footnote.
 *  §63 the detection method is a visible badge — an inference never looks like
 *      an observation.
 */

import React from 'react';
import { AnimatePresence, motion } from 'motion/react';
import {
  AlertTriangle, Check, ChevronDown, ChevronRight, CircleDashed, Copy, Download,
  FileJson, FileSpreadsheet, Info, Loader2, MinusCircle, Search, ShieldAlert,
  ShieldCheck, Sparkles, X, XCircle,
} from 'lucide-react';
import { cn } from '@/lib/utils';
import { ACCENT, Panel, SectionLabel } from '@/components/quantum-scan/ui';
import type {
  CbomComponent,
  CorrelatedExposure,
  EngineRun,
  ExposureAssessment,
  ExposureFinding,
  FindingConfidence,
  FindingSeverity,
  QuantumStatus,
  ScanCoverage,
  ScanMode,
} from '@/lib/scanner/exposure/types';
import { SEVERITY_ORDER } from '@/lib/scanner/exposure/types';
import { completenessNote, reconcileExposure, withUnit } from '@/lib/scanner/exposure/exposure-truth';
import { layerLabel } from '@/lib/scanner/exposure/correlate';
import { CAPABILITY_LABEL, type EngineDescriptor } from '@/lib/scanner/exposure/engine-contract';
import type { ScanProfile } from '@/lib/scanner/exposure/profiles';

/* ────────────────────────────────────────────────────────────── vocabulary ── */

export const SEVERITY_COLOR: Record<FindingSeverity, string> = {
  critical: ACCENT.rose,
  high: '#fb923c',
  medium: ACCENT.amber,
  low: ACCENT.blue,
  info: ACCENT.slate,
};

export const QUANTUM_COLOR: Record<QuantumStatus, string> = {
  vulnerable: ACCENT.rose,
  hybrid: ACCENT.violet,
  pqc: ACCENT.emerald,
  resistant: ACCENT.cyan,
  unknown: ACCENT.slate,
  'not-applicable': '#475569',
};

export const QUANTUM_LABEL: Record<QuantumStatus, string> = {
  vulnerable: 'Quantum Vulnerable',
  hybrid: 'Hybrid',
  pqc: 'Post-Quantum',
  resistant: 'Quantum Resistant',
  unknown: 'Unknown',
  'not-applicable': 'Not Applicable',
};

const CONFIDENCE_LABEL: Record<FindingConfidence, string> = {
  high: 'High confidence',
  medium: 'Medium confidence',
  low: 'Low confidence',
  unknown: 'Unknown confidence',
};

const DETECTION_LABEL: Record<string, string> = {
  observed: 'Observed',
  inferred: 'Inferred',
  potential: 'Potential',
  unknown: 'Unknown',
};

const ENGINE_STATE_STYLE: Record<string, { color: string; label: string }> = {
  pending: { color: ACCENT.slate, label: 'Queued' },
  running: { color: ACCENT.cyan, label: 'Running' },
  completed: { color: ACCENT.emerald, label: 'Complete' },
  failed: { color: ACCENT.rose, label: 'Failed' },
  skipped: { color: ACCENT.slate, label: 'Skipped' },
  'not-applicable': { color: '#475569', label: 'Not Applicable' },
  'not-assessed': { color: ACCENT.amber, label: 'Not Assessed' },
  cancelled: { color: ACCENT.slate, label: 'Cancelled' },
};

/* ──────────────────────────────────────────────────────────── disclosure ─── */

/**
 * States that a list is showing only part of what was found.
 *
 * A table that quietly stops at its cap is the most deniable way a dashboard
 * lies: the reader has no way to tell a complete list from a truncated one, and
 * every number they derive by counting rows is wrong. Renders nothing when the
 * list is whole.
 */
export function ListTruncationNote({
  shown,
  total,
  noun,
  rank = 'most significant',
}: {
  shown: number;
  total: number;
  noun: string;
  rank?: string;
}) {
  if (!Number.isFinite(total) || total <= shown) return null;
  return (
    <p className="border-t border-white/[0.06] px-5 py-2.5 font-mono text-[10.5px] text-slate-500">
      Showing the {shown.toLocaleString()} {rank} of {total.toLocaleString()} {noun}. The scores and totals above are
      computed over all {total.toLocaleString()}.
    </p>
  );
}

/* ───────────────────────────────────────────────────────────────── badges ─── */

export function SeverityBadge({ severity }: { severity: FindingSeverity }) {
  const color = SEVERITY_COLOR[severity];
  return (
    <span
      className="inline-flex shrink-0 items-center rounded px-1.5 py-0.5 font-mono text-[9.5px] font-black uppercase tracking-[0.14em]"
      style={{ backgroundColor: `${color}1f`, color }}
    >
      {severity}
    </span>
  );
}

/**
 * Confidence is a SEPARATE badge from severity, always (§37).
 *
 * A Critical/Low pair means "this would be very bad if it is real, and we are
 * not sure it is". Rendering one number would erase exactly the information an
 * engineer needs to decide whether to act now or verify first.
 */
export function ConfidenceBadge({ confidence, detection }: { confidence: FindingConfidence; detection?: string }) {
  const tone =
    confidence === 'high' ? ACCENT.emerald : confidence === 'medium' ? ACCENT.cyan : confidence === 'low' ? ACCENT.amber : ACCENT.slate;
  return (
    <span
      className="inline-flex shrink-0 items-center gap-1 rounded border px-1.5 py-0.5 font-mono text-[9.5px] font-bold uppercase tracking-[0.12em]"
      style={{ borderColor: `${tone}44`, color: tone }}
      title={`${CONFIDENCE_LABEL[confidence]}${detection ? ` · ${DETECTION_LABEL[detection] ?? detection}` : ''}`}
    >
      {confidence}
      {detection && <span className="text-slate-500">· {DETECTION_LABEL[detection] ?? detection}</span>}
    </span>
  );
}

export function QuantumBadge({ status }: { status: QuantumStatus }) {
  const color = QUANTUM_COLOR[status];
  return (
    <span
      className="inline-flex shrink-0 items-center rounded px-1.5 py-0.5 font-mono text-[9.5px] font-bold uppercase tracking-[0.12em]"
      style={{ backgroundColor: `${color}18`, color }}
    >
      {QUANTUM_LABEL[status]}
    </span>
  );
}

/* ──────────────────────────────────────────────────── profile + engine picker ─ */

export function ScanProfileSelector({
  profiles,
  value,
  onChange,
  disabledIds,
  suggested,
}: {
  profiles: ScanProfile[];
  value: string;
  onChange: (id: string) => void;
  disabledIds?: Set<string>;
  /** The Smart Scan Planner's suggestion, badged so the operator sees why. */
  suggested?: string | null;
}) {
  return (
    <div role="radiogroup" aria-label="Scan profile" className="grid grid-cols-[minmax(0,1fr)] gap-2 sm:grid-cols-2">
      {profiles.map((profile) => {
        const active = value === profile.id;
        const locked = disabledIds?.has(profile.id);
        return (
          <button
            key={profile.id}
            type="button"
            role="radio"
            aria-checked={active}
            disabled={locked}
            onClick={() => !locked && onChange(profile.id)}
            className={cn(
              'group rounded-xl border px-3.5 py-3 text-left transition-colors focus-visible:outline-none focus-visible:ring-2 focus-visible:ring-cyan-400/50',
              active
                ? 'border-cyan-400/40 bg-cyan-400/[0.07]'
                : 'border-white/[0.07] bg-white/[0.02] hover:border-white/15',
              locked && 'cursor-not-allowed opacity-45',
            )}
          >
            <div className="flex items-center justify-between gap-2">
              <span className={cn('text-[13px] font-black', active ? 'text-cyan-300' : 'text-white')}>{profile.label}</span>
              <div className="flex shrink-0 items-center gap-1.5">
                {suggested === profile.id && (
                  <span className="rounded bg-violet-400/15 px-1.5 py-0.5 font-mono text-[9px] font-black uppercase tracking-widest text-violet-300">
                    Suggested
                  </span>
                )}
                {profile.minTier && (
                  <span className="rounded bg-amber-400/15 px-1.5 py-0.5 font-mono text-[9px] font-black uppercase tracking-widest text-amber-300">
                    {profile.minTier}
                  </span>
                )}
                {active && <Check className="h-3.5 w-3.5 text-cyan-300" />}
              </div>
            </div>
            <p className="mt-1 text-[11.5px] leading-snug text-slate-400">{profile.description}</p>
            <ul className="mt-2 flex flex-wrap gap-1">
              {profile.covers.slice(0, 4).map((item) => (
                <li key={item} className="rounded bg-white/[0.05] px-1.5 py-0.5 font-mono text-[9px] text-slate-400">
                  {item}
                </li>
              ))}
              {profile.covers.length > 4 && (
                <li className="rounded bg-white/[0.05] px-1.5 py-0.5 font-mono text-[9px] text-slate-500">
                  +{profile.covers.length - 4}
                </li>
              )}
            </ul>
          </button>
        );
      })}
    </div>
  );
}

/**
 * Horizontal profile rail — pick a profile, read what it does, launch.
 *
 * The card grid above works when there are a handful of profiles in a narrow
 * column. Dev mode offers twelve, and stacked two-across they pushed the
 * primary action — the button that actually starts the assessment — a screen
 * and a half below the fold. An operator had to scroll to discover both what
 * the choices were and how to commit to one.
 *
 * So the choice and the description are separated: every profile is a compact
 * chip on one rail, always all visible, and only the SELECTED profile spends
 * vertical space explaining itself. The launch control sits beside that
 * explanation, on the same screen as the thing it launches.
 *
 * Keyboard behaviour follows the radiogroup pattern: Tab reaches the group
 * once, then arrows move the selection, Home/End jump to the ends.
 */
export function ScanProfileRail({
  profiles,
  value,
  onChange,
  disabledIds,
  suggested,
  engineCount,
  launchSlot,
}: {
  profiles: ScanProfile[];
  value: string;
  onChange: (id: string) => void;
  disabledIds?: Set<string>;
  /** The Smart Scan Planner's suggestion, badged so the operator sees why. */
  suggested?: string | null;
  /** How many engines the current selection resolves to. */
  engineCount: number;
  /** The primary action and its hints, supplied by the mode that owns them. */
  launchSlot?: React.ReactNode;
}) {
  const buttonRefs = React.useRef<Array<HTMLButtonElement | null>>([]);
  const selected = profiles.find((profile) => profile.id === value) ?? null;

  const selectableIndexes = React.useMemo(
    () => profiles.map((profile, index) => (disabledIds?.has(profile.id) ? -1 : index)).filter((index) => index >= 0),
    [profiles, disabledIds],
  );

  const move = (from: number, direction: 1 | -1 | 'first' | 'last') => {
    if (selectableIndexes.length === 0) return;
    let target: number;
    if (direction === 'first') target = selectableIndexes[0];
    else if (direction === 'last') target = selectableIndexes[selectableIndexes.length - 1];
    else {
      const position = selectableIndexes.indexOf(from);
      const next = (position + direction + selectableIndexes.length) % selectableIndexes.length;
      target = selectableIndexes[next];
    }
    onChange(profiles[target].id);
    buttonRefs.current[target]?.focus();
  };

  return (
    <div className="space-y-4">
      {/* ── the rail ───────────────────────────────────────────────────── */}
      <div role="radiogroup" aria-label="Scan profile" className="flex flex-wrap gap-1.5">
        {profiles.map((profile, index) => {
          const active = value === profile.id;
          const locked = disabledIds?.has(profile.id);
          return (
            <button
              key={profile.id}
              ref={(node) => {
                buttonRefs.current[index] = node;
              }}
              type="button"
              role="radio"
              aria-checked={active}
              disabled={locked}
              tabIndex={active ? 0 : -1}
              onClick={() => !locked && onChange(profile.id)}
              onKeyDown={(event) => {
                if (event.key === 'ArrowRight' || event.key === 'ArrowDown') {
                  event.preventDefault();
                  move(index, 1);
                } else if (event.key === 'ArrowLeft' || event.key === 'ArrowUp') {
                  event.preventDefault();
                  move(index, -1);
                } else if (event.key === 'Home') {
                  event.preventDefault();
                  move(index, 'first');
                } else if (event.key === 'End') {
                  event.preventDefault();
                  move(index, 'last');
                }
              }}
              title={locked ? `${profile.label} requires the ${profile.minTier} plan.` : profile.description}
              className={cn(
                'group inline-flex items-center gap-1.5 rounded-lg border px-3 py-2 text-[12.5px] font-bold transition-all',
                'focus-visible:outline-none focus-visible:ring-2 focus-visible:ring-cyan-400/50',
                active
                  ? 'border-cyan-400/50 bg-cyan-400/[0.1] text-cyan-200 shadow-[0_0_20px_-8px_rgba(34,211,238,0.7)]'
                  : 'border-white/[0.08] bg-white/[0.02] text-slate-300 hover:border-white/20 hover:text-white',
                locked && 'cursor-not-allowed opacity-45 hover:border-white/[0.08] hover:text-slate-300',
              )}
            >
              {active && <Check aria-hidden className="h-3.5 w-3.5 shrink-0" />}
              {profile.label}
              {suggested === profile.id && !active && (
                <span className="rounded bg-violet-400/15 px-1.5 py-0.5 font-mono text-[8.5px] font-black uppercase tracking-widest text-violet-300">
                  Suggested
                </span>
              )}
              {profile.minTier && (
                <span className="rounded bg-amber-400/15 px-1.5 py-0.5 font-mono text-[8.5px] font-black uppercase tracking-widest text-amber-300">
                  {profile.minTier}
                </span>
              )}
            </button>
          );
        })}
      </div>

      {/* ── what the selection means, and how to run it ─────────────────── */}
      <div className="grid grid-cols-[minmax(0,1fr)] gap-4 xl:grid-cols-[minmax(0,1fr)_minmax(0,22rem)]">
        <div className="min-w-0 rounded-xl border border-white/[0.07] bg-white/[0.02] px-4 py-3.5">
          {selected ? (
            <>
              <div className="flex flex-wrap items-center gap-2">
                <h4 className="text-[14px] font-black text-white">{selected.label}</h4>
                <span className="rounded-md border border-cyan-400/25 bg-cyan-400/[0.07] px-2 py-0.5 font-mono text-[10px] font-bold text-cyan-300">
                  {engineCount} engine{engineCount === 1 ? '' : 's'}
                </span>
                {suggested === selected.id && (
                  <span className="rounded-md bg-violet-400/15 px-2 py-0.5 font-mono text-[9.5px] font-black uppercase tracking-widest text-violet-300">
                    Planner suggested
                  </span>
                )}
              </div>
              <p className="mt-1.5 text-[12.5px] leading-relaxed text-slate-400">{selected.description}</p>
              {selected.covers.length > 0 && (
                <>
                  <p className="mt-3 font-mono text-[9px] font-bold uppercase tracking-[0.18em] text-slate-500">
                    What it covers
                  </p>
                  <ul className="mt-1.5 flex flex-wrap gap-1.5">
                    {selected.covers.map((item) => (
                      <li
                        key={item}
                        className="rounded-md bg-white/[0.05] px-2 py-0.5 font-mono text-[10px] text-slate-300"
                      >
                        {item}
                      </li>
                    ))}
                  </ul>
                </>
              )}
            </>
          ) : (
            <p className="text-[12.5px] text-slate-500">Select a profile to see what it runs.</p>
          )}
        </div>

        {launchSlot && <div className="min-w-0">{launchSlot}</div>}
      </div>
    </div>
  );
}

/**
 * Custom engine selector (§30, §31).
 *
 * Engines that the planner says are irrelevant to THIS target are still listed
 * — with the reason — rather than hidden. Hiding them would leave the operator
 * unable to tell "not offered" from "not applicable".
 */
export function ScanEngineSelector({
  engines,
  selected,
  onToggle,
  recommended,
  health,
}: {
  engines: EngineDescriptor[];
  selected: Set<string>;
  onToggle: (id: string) => void;
  recommended?: Map<string, string>;
  health?: Map<string, { state: string; detail: string }>;
}) {
  const grouped = React.useMemo(() => {
    const map = new Map<string, EngineDescriptor[]>();
    for (const engine of engines) {
      const key = CAPABILITY_LABEL[engine.capability];
      const list = map.get(key) ?? [];
      list.push(engine);
      map.set(key, list);
    }
    return [...map.entries()].sort((a, b) => a[0].localeCompare(b[0]));
  }, [engines]);

  return (
    <div className="space-y-3">
      {grouped.map(([capability, list]) => (
        <div key={capability}>
          <p className="font-mono text-[9.5px] font-bold uppercase tracking-[0.18em] text-slate-500">{capability}</p>
          <div className="mt-1.5 space-y-1.5">
            {list.map((engine) => {
              const checked = selected.has(engine.id);
              const reason = recommended?.get(engine.id);
              const engineHealth = health?.get(engine.id);
              const unhealthy = engineHealth && engineHealth.state !== 'healthy';
              const required = engine.id === 'file-discovery';

              return (
                <label
                  key={engine.id}
                  className={cn(
                    'flex cursor-pointer items-start gap-2.5 rounded-lg border px-3 py-2 transition-colors',
                    checked ? 'border-cyan-400/25 bg-cyan-400/[0.05]' : 'border-white/[0.06] bg-white/[0.015] hover:border-white/12',
                    required && 'cursor-not-allowed opacity-80',
                  )}
                >
                  <input
                    type="checkbox"
                    checked={checked}
                    disabled={required}
                    onChange={() => onToggle(engine.id)}
                    className="mt-0.5 h-3.5 w-3.5 shrink-0 accent-cyan-400"
                  />
                  <span className="min-w-0 flex-1">
                    <span className="flex flex-wrap items-center gap-1.5">
                      <span className="text-[12.5px] font-bold text-white">{engine.label}</span>
                      {required && (
                        <span className="rounded bg-white/[0.07] px-1 py-0.5 font-mono text-[8.5px] uppercase tracking-widest text-slate-400">
                          always runs
                        </span>
                      )}
                      {reason && (
                        <span className="rounded bg-violet-400/12 px-1 py-0.5 font-mono text-[8.5px] uppercase tracking-widest text-violet-300">
                          recommended
                        </span>
                      )}
                      {engine.minTier && (
                        <span className="rounded bg-amber-400/12 px-1 py-0.5 font-mono text-[8.5px] uppercase tracking-widest text-amber-300">
                          {engine.minTier}
                        </span>
                      )}
                      {unhealthy && (
                        <span
                          title={engineHealth?.detail}
                          className="rounded bg-rose-400/12 px-1 py-0.5 font-mono text-[8.5px] uppercase tracking-widest text-rose-300"
                        >
                          {engineHealth?.state}
                        </span>
                      )}
                    </span>
                    <span className="mt-0.5 block text-[11px] leading-snug text-slate-400">{engine.description}</span>
                    {reason && <span className="mt-0.5 block text-[10.5px] italic text-violet-300/70">{reason}</span>}
                  </span>
                </label>
              );
            })}
          </div>
        </div>
      ))}
    </div>
  );
}

/* ───────────────────────────────────────────────────────── live engine rail ── */

/** The live ledger (§50). One row per selected engine, always terminal. */
export function EngineLedger({
  runs,
  progress,
  status,
  currentStep,
  onCancel,
}: {
  runs: EngineRun[];
  progress: number;
  status: string;
  currentStep?: string | null;
  onCancel?: () => void;
}) {
  const settled = runs.filter((run) => run.state !== 'pending' && run.state !== 'running').length;

  return (
    <Panel className="overflow-hidden">
      {/* "Engine Ledger", not "Scanner Engines": this panel is THIS assessment's
          execution record, while the registry panel below it lists the engines
          the platform has and whether they are healthy. Both were once called
          the same thing, which left two adjacent panels claiming one identity. */}
      <div className="flex items-center justify-between gap-3 border-b border-white/[0.06] px-4 py-3">
        <SectionLabel>Engine Ledger</SectionLabel>
        <div className="flex shrink-0 items-center gap-2">
          <span className="font-mono text-[10px] font-bold text-slate-400">
            {settled}/{runs.length}
          </span>
          {status === 'scanning' && (
            <span className="flex items-center gap-1.5 font-mono text-[10px] font-bold text-cyan-300">
              <Loader2 className="h-3 w-3 animate-spin" />
              {progress}%
            </span>
          )}
          {status === 'scanning' && onCancel && (
            <button
              type="button"
              onClick={onCancel}
              className="rounded border border-rose-400/25 px-2 py-0.5 font-mono text-[9.5px] font-bold uppercase tracking-widest text-rose-300 transition-colors hover:bg-rose-400/10"
            >
              Cancel
            </button>
          )}
        </div>
      </div>

      <ol className="max-h-[26rem] space-y-1 overflow-y-auto px-4 py-3">
        {runs.map((run) => {
          const style = ENGINE_STATE_STYLE[run.state] ?? ENGINE_STATE_STYLE.pending;
          return (
            <li key={run.engineId} className="flex items-start gap-2.5 py-1.5">
              <span
                aria-hidden
                className="relative mt-0.5 grid h-6 w-6 shrink-0 place-items-center rounded-full border"
                style={{ borderColor: `${style.color}55`, backgroundColor: `${style.color}12`, color: style.color }}
              >
                {run.state === 'completed' ? (
                  <Check className="h-3 w-3" />
                ) : run.state === 'failed' ? (
                  <XCircle className="h-3 w-3" />
                ) : run.state === 'not-applicable' || run.state === 'skipped' ? (
                  <MinusCircle className="h-3 w-3" />
                ) : run.state === 'not-assessed' ? (
                  <AlertTriangle className="h-3 w-3" />
                ) : run.state === 'running' ? (
                  <Loader2 className="h-3 w-3 animate-spin" />
                ) : (
                  <CircleDashed className="h-3 w-3" />
                )}
              </span>

              <div className="min-w-0 flex-1">
                <div className="flex items-baseline justify-between gap-2">
                  <p className="truncate text-[12.5px] font-bold text-slate-200">{run.label}</p>
                  <span className="shrink-0 font-mono text-[9px] uppercase tracking-widest" style={{ color: style.color }}>
                    {style.label}
                  </span>
                </div>
                <p className="truncate text-[10.5px] text-slate-500" title={run.detail || run.step}>
                  {run.state === 'running' && run.units
                    ? `${run.step ?? 'Working'} · ${run.units.done}/${run.units.total} ${run.units.unit}`
                    : run.detail || run.step || (run.findingCount ? `${run.findingCount} finding${run.findingCount === 1 ? '' : 's'}` : '—')}
                </p>
                {run.state === 'running' && run.units && run.units.total > 0 && (
                  <div className="mt-1 h-[2px] w-full overflow-hidden rounded-full bg-white/[0.06]">
                    <motion.div
                      className="h-full bg-cyan-400"
                      animate={{ width: `${Math.min(100, Math.round((run.units.done / run.units.total) * 100))}%` }}
                      transition={{ duration: 0.3 }}
                    />
                  </div>
                )}
              </div>

              {run.findingCount > 0 && (
                <span className="mt-0.5 shrink-0 rounded bg-white/[0.06] px-1.5 py-0.5 font-mono text-[9.5px] text-slate-300">
                  {run.findingCount}
                </span>
              )}
            </li>
          );
        })}
      </ol>

      {currentStep && (
        <p className="truncate border-t border-white/[0.06] px-4 py-2 font-mono text-[10px] text-slate-500">{currentStep}</p>
      )}

      <div className="h-1 w-full bg-white/[0.05]">
        <motion.div
          className="h-full bg-gradient-to-r from-cyan-400 to-violet-500"
          animate={{ width: `${progress}%` }}
          transition={{ duration: 0.4, ease: 'easeOut' }}
        />
      </div>
    </Panel>
  );
}

/* ─────────────────────────────────────────────────────────── score summary ── */

/** The five-reading decomposition (§40). Never collapsed into one number. */
export function ExposureScorecard({ assessment }: { assessment: ExposureAssessment }) {
  const { scores } = assessment.task;
  /* Read, never recomputed. The reconciler is the one place that knows which
     population each unit counts, and this panel is where a reader most often
     tries to reconcile a score against a severity count they saw elsewhere. */
  const truth = React.useMemo(() => reconcileExposure(assessment), [assessment]);
  const rows: Array<{ label: string; value: number | null; band: string | null; invert: boolean; hint: string }> = [
    { label: 'Security Risk', value: scores.securityRisk, band: scores.securityBand, invert: true, hint: scores.basis[0] ?? '' },
    { label: 'Quantum Risk', value: scores.quantumRisk, band: scores.quantumBand, invert: true, hint: scores.basis[1] ?? '' },
    { label: 'Migration Risk', value: scores.migrationRisk, band: scores.migrationBand, invert: true, hint: scores.basis[2] ?? '' },
    { label: 'Coverage', value: scores.coverage, band: null, invert: false, hint: scores.basis[3] ?? '' },
    { label: 'Confidence', value: scores.confidence, band: null, invert: false, hint: scores.basis[4] ?? '' },
  ];

  return (
    <Panel className="overflow-hidden">
      <div className="flex flex-wrap items-center justify-between gap-2 border-b border-white/[0.06] px-5 py-3">
        <SectionLabel>Risk Decomposition</SectionLabel>
        <span className="font-mono text-[10px] text-slate-500">
          {withUnit(assessment.exposures.length, 'exposure')} · {withUnit(assessment.findings.length, 'finding')}
        </span>
      </div>

      {/* The population, said out loud and BEFORE the numbers. Without it, a
          reader who has just seen "1 critical" on the findings donut reads
          "99/100" as a contradiction rather than as a different unit. */}
      {truth.scoreUnitNote && (
        <p className="border-b border-white/[0.06] px-5 py-2.5 text-[11px] leading-relaxed text-slate-500">
          {truth.scoreUnitNote}
        </p>
      )}

      <div className="grid grid-cols-[minmax(0,1fr)] divide-y divide-white/[0.05] sm:grid-cols-5 sm:divide-x sm:divide-y-0">
        {rows.map((row) => {
          const color = row.value === null
            ? ACCENT.slate
            : row.invert
              ? row.value >= 60 ? ACCENT.rose : row.value >= 35 ? ACCENT.amber : ACCENT.emerald
              : row.value >= 80 ? ACCENT.emerald : row.value >= 50 ? ACCENT.cyan : ACCENT.amber;
          return (
            <div key={row.label} className="px-5 py-4" title={row.hint}>
              <p className="font-mono text-[9.5px] font-bold uppercase tracking-[0.16em] text-slate-500">{row.label}</p>
              <p className="mt-1.5 font-mono text-[26px] font-black leading-none" style={{ color }}>
                {row.value === null ? '—' : row.value}
                {row.value !== null && <span className="text-[13px] font-bold text-slate-600">{row.invert ? '/100' : '%'}</span>}
              </p>
              <p className="mt-1 font-mono text-[9.5px] uppercase tracking-widest" style={{ color: row.value === null ? ACCENT.slate : color }}>
                {row.value === null ? 'Not measured' : (row.band ?? '')}
              </p>
            </div>
          );
        })}
      </div>
      <div className="space-y-1 border-t border-white/[0.06] bg-white/[0.015] px-5 py-3">
        {scores.basis.map((line, index) => (
          <p key={index} className="text-[11px] leading-relaxed text-slate-500">
            {line}
          </p>
        ))}
      </div>
    </Panel>
  );
}

/* ──────────────────────────────────────────────────────── quantum summary ─── */

export function QuantumExposureSummary({ assessment }: { assessment: ExposureAssessment }) {
  const { topAlgorithms } = assessment.intelligence;
  /* Reconciled, and the UNIT is stated. These cells count CBOM components; the
     Findings table below counts findings. Both are correct and they legitimately
     differ — several findings can attach to one component. Saying so is what
     stops "Vulnerable 5" here and "12 vulnerable" in the filter reading as a
     contradiction. */
  const truth = React.useMemo(() => reconcileExposure(assessment), [assessment]);
  const quantum = truth.components;
  const cells: Array<{ label: string; value: number; status: QuantumStatus }> = [
    { label: 'Vulnerable', value: quantum.vulnerable, status: 'vulnerable' },
    { label: 'Hybrid', value: quantum.hybrid, status: 'hybrid' },
    { label: 'Post-Quantum', value: quantum.pqc, status: 'pqc' },
    { label: 'Resistant', value: quantum.resistant, status: 'resistant' },
    { label: 'Unknown', value: quantum.unknown, status: 'unknown' },
  ];

  return (
    <Panel className="overflow-hidden">
      <div className="flex flex-wrap items-center justify-between gap-2 border-b border-white/[0.06] px-5 py-3">
        <SectionLabel accent={ACCENT.violet}>Quantum Exposure</SectionLabel>
        <span className="font-mono text-[10px] text-slate-500">
          {truth.readiness === null ? 'Readiness not measured' : `Readiness ${truth.readiness}%`}
        </span>
      </div>
      {/* The unit, said out loud and before the numbers. */}
      <p className="border-b border-white/[0.06] px-5 py-2 font-mono text-[9.5px] uppercase tracking-[0.14em] text-slate-500">
        Counting cryptographic components · the unit a migration replaces
      </p>

      <div className="grid grid-cols-2 gap-px bg-white/[0.05] sm:grid-cols-5">
        {cells.map((cell) => (
          <div key={cell.label} className="bg-[#080d1a] px-4 py-3.5">
            <p className="font-mono text-[9px] font-bold uppercase tracking-[0.14em] text-slate-500">{cell.label}</p>
            <p className="mt-1 font-mono text-[22px] font-black leading-none" style={{ color: QUANTUM_COLOR[cell.status] }}>
              {cell.value}
            </p>
          </div>
        ))}
      </div>

      {truth.readiness === null && (
        <p className="border-t border-white/[0.06] bg-amber-400/[0.05] px-5 py-2.5 text-[11.5px] leading-relaxed text-amber-100/80">
          {truth.readinessReason}
        </p>
      )}

      {/* Why this panel and the Findings table below show different numbers.
          Rendered only when they actually differ. */}
      {truth.unitNote && (
        <p className="border-t border-white/[0.06] px-5 py-2.5 text-[11px] leading-relaxed text-slate-500">
          {truth.unitNote}
        </p>
      )}

      {/* A total computed over a partial scan reads as a total over the estate. */}
      {completenessNote(truth) && (
        <p className="border-t border-amber-400/20 bg-amber-400/[0.05] px-5 py-2.5 text-[11px] leading-relaxed text-amber-100/85">
          {completenessNote(truth)}
        </p>
      )}

      {topAlgorithms.length > 0 && (
        <div className="border-t border-white/[0.06] px-5 py-3">
          <p className="font-mono text-[9.5px] font-bold uppercase tracking-[0.16em] text-slate-500">Algorithms observed</p>
          <div className="mt-2 flex flex-wrap gap-1.5">
            {topAlgorithms.map((entry) => (
              <span
                key={entry.algorithm}
                className="inline-flex items-center gap-1.5 rounded-lg border px-2 py-1 text-[11px]"
                style={{ borderColor: `${QUANTUM_COLOR[entry.quantumStatus]}33`, color: QUANTUM_COLOR[entry.quantumStatus] }}
              >
                <span className="font-bold">{entry.algorithm}</span>
                <span className="font-mono text-[10px] text-slate-500">×{entry.count}</span>
              </span>
            ))}
          </div>
        </div>
      )}
    </Panel>
  );
}

/* ────────────────────────────────────────────────────────── findings table ── */

/** Findings with the filter set §51 asks for, and the detail panel of §52. */
export function FindingExplorer({ assessment }: { assessment: ExposureAssessment }) {
  const [severity, setSeverity] = React.useState<Set<FindingSeverity>>(new Set());
  const [quantum, setQuantum] = React.useState<Set<QuantumStatus>>(new Set());
  const [engineId, setEngineId] = React.useState<string>('');
  const [query, setQuery] = React.useState('');
  const [selected, setSelected] = React.useState<ExposureFinding | null>(null);
  const [limit, setLimit] = React.useState(50);

  const engines = React.useMemo(
    () => [...new Map(assessment.intelligence.byEngine.map((entry) => [entry.engineId, entry])).values()].filter((entry) => entry.findings > 0),
    [assessment],
  );

  const filtered = React.useMemo(() => {
    const needle = query.trim().toLowerCase();
    return assessment.findings
      .filter((finding) => {
        if (severity.size && !severity.has(finding.severity)) return false;
        if (quantum.size && !quantum.has(finding.quantumStatus)) return false;
        if (engineId && finding.engineId !== engineId) return false;
        if (needle) {
          const haystack = `${finding.title} ${finding.description} ${finding.canonicalAlgorithm ?? ''} ${finding.evidence[0]?.file ?? ''}`.toLowerCase();
          if (!haystack.includes(needle)) return false;
        }
        return true;
      })
      .sort((a, b) => SEVERITY_ORDER[a.severity] - SEVERITY_ORDER[b.severity]);
  }, [assessment.findings, severity, quantum, engineId, query]);

  const toggle = <T,>(set: Set<T>, value: T, apply: (next: Set<T>) => void) => {
    const next = new Set(set);
    if (next.has(value)) next.delete(value);
    else next.add(value);
    apply(next);
  };

  const visible = filtered.slice(0, limit);

  return (
    <>
      <Panel className="overflow-hidden">
        <div className="flex flex-wrap items-center justify-between gap-3 border-b border-white/[0.06] px-5 py-3">
          <SectionLabel>Findings</SectionLabel>
          <span className="font-mono text-[10px] text-slate-500">
            {/* "findings", not a bare number — the Quantum Exposure panel above
                counts components, and an unlabelled total invites the reader to
                compare two different units. */}
            {filtered.length === assessment.findings.length
              ? `${assessment.findings.length} finding${assessment.findings.length === 1 ? '' : 's'}`
              : `${filtered.length} of ${assessment.findings.length} findings`}
          </span>
        </div>

        {/* ── filters (§51) ─────────────────────────────────────────────── */}
        <div className="space-y-2.5 border-b border-white/[0.06] bg-white/[0.015] px-5 py-3">
          <div className="flex flex-wrap items-center gap-1.5">
            <span className="font-mono text-[9px] uppercase tracking-widest text-slate-600">Severity</span>
            {(['critical', 'high', 'medium', 'low', 'info'] as FindingSeverity[]).map((value) => (
              <FilterChip
                key={value}
                label={value}
                active={severity.has(value)}
                color={SEVERITY_COLOR[value]}
                count={assessment.intelligence.severity[value]}
                onClick={() => toggle(severity, value, setSeverity)}
              />
            ))}
          </div>
          <div className="flex flex-wrap items-center gap-1.5">
            <span className="font-mono text-[9px] uppercase tracking-widest text-slate-600">Quantum</span>
            {(['vulnerable', 'hybrid', 'pqc', 'resistant', 'unknown'] as QuantumStatus[]).map((value) => (
              <FilterChip
                key={value}
                label={QUANTUM_LABEL[value]}
                active={quantum.has(value)}
                color={QUANTUM_COLOR[value]}
                onClick={() => toggle(quantum, value, setQuantum)}
              />
            ))}
          </div>
          <div className="flex flex-wrap items-center gap-2">
            <select
              value={engineId}
              onChange={(event) => setEngineId(event.target.value)}
              aria-label="Filter by engine"
              className="rounded-lg border border-white/[0.08] bg-[#050a15] px-2 py-1.5 text-[11.5px] text-slate-300 outline-none focus:border-cyan-400/40"
            >
              <option value="">All engines</option>
              {engines.map((engine) => (
                <option key={engine.engineId} value={engine.engineId}>
                  {engine.label} ({engine.findings})
                </option>
              ))}
            </select>
            <div className="flex min-w-[12rem] flex-1 items-center gap-1.5 rounded-lg border border-white/[0.08] bg-[#050a15] px-2.5 py-1.5">
              <Search aria-hidden className="h-3.5 w-3.5 shrink-0 text-slate-600" />
              <input
                value={query}
                onChange={(event) => setQuery(event.target.value)}
                placeholder="Search title, algorithm or file"
                className="min-w-0 flex-1 bg-transparent text-[11.5px] text-slate-200 outline-none placeholder:text-slate-600"
              />
            </div>
          </div>
        </div>

        {/* ── rows ──────────────────────────────────────────────────────── */}
        {visible.length === 0 ? (
          <div className="px-5 py-10 text-center">
            <ShieldCheck aria-hidden className="mx-auto h-8 w-8 text-slate-700" />
            <p className="mt-2 text-[13px] font-bold text-slate-300">
              {assessment.findings.length === 0 ? 'No findings were produced' : 'No findings match these filters'}
            </p>
            <p className="mt-1 text-[11.5px] text-slate-500">
              {assessment.findings.length === 0
                ? 'Check the coverage panel below — an engine that reported "Not Applicable" found nothing because it had nothing in scope to read, which is different from a clean result.'
                : 'Clear a filter to see the rest.'}
            </p>
          </div>
        ) : (
          <ul className="divide-y divide-white/[0.04]">
            {visible.map((finding) => (
              <li key={finding.id}>
                <button
                  type="button"
                  onClick={() => setSelected(finding)}
                  className="flex w-full items-start gap-3 px-5 py-3 text-left transition-colors hover:bg-white/[0.02]"
                >
                  <span
                    aria-hidden
                    className="mt-1.5 h-2 w-2 shrink-0 rounded-full"
                    style={{ backgroundColor: SEVERITY_COLOR[finding.severity] }}
                  />
                  <span className="min-w-0 flex-1">
                    <span className="flex flex-wrap items-center gap-1.5">
                      <span className="text-[12.5px] font-bold text-white">{finding.title}</span>
                      <SeverityBadge severity={finding.severity} />
                      <ConfidenceBadge confidence={finding.confidence} detection={finding.detection} />
                      {finding.quantumStatus !== 'not-applicable' && <QuantumBadge status={finding.quantumStatus} />}
                    </span>
                    <span className="mt-1 block truncate text-[11px] text-slate-500">
                      {finding.evidence[0]?.file
                        ? `${finding.evidence[0].file}${finding.evidence[0].line ? `:${finding.evidence[0].line}` : ''}`
                        : finding.evidence[0]?.reference ?? layerLabel(finding.layer)}
                    </span>
                  </span>
                  <ChevronRight aria-hidden className="mt-1 h-4 w-4 shrink-0 text-slate-600" />
                </button>
              </li>
            ))}
          </ul>
        )}

        {filtered.length > visible.length && (
          <button
            type="button"
            onClick={() => setLimit((current) => current + 100)}
            className="w-full border-t border-white/[0.06] px-5 py-2.5 text-[11.5px] font-semibold text-cyan-300 transition-colors hover:bg-cyan-400/[0.05]"
          >
            Show {Math.min(100, filtered.length - visible.length)} more of {filtered.length}
          </button>
        )}
      </Panel>

      <FindingDetail finding={selected} onClose={() => setSelected(null)} exposures={assessment.exposures} />
    </>
  );
}

function FilterChip({
  label,
  active,
  color,
  count,
  onClick,
}: {
  label: string;
  active: boolean;
  color: string;
  count?: number;
  onClick: () => void;
}) {
  return (
    <button
      type="button"
      aria-pressed={active}
      onClick={onClick}
      className={cn(
        'inline-flex items-center gap-1 rounded border px-1.5 py-0.5 font-mono text-[9.5px] font-bold uppercase tracking-[0.12em] transition-colors',
        active ? 'border-current' : 'border-white/[0.08] text-slate-500 hover:text-slate-300',
      )}
      style={active ? { color, backgroundColor: `${color}14` } : undefined}
    >
      {label}
      {count !== undefined && count > 0 && <span className="text-slate-500">{count}</span>}
    </button>
  );
}

/* ─────────────────────────────────────────────────────────── finding detail ─ */

/** The evidence panel (§52). Everything needed to reproduce the observation. */
export function FindingDetail({
  finding,
  onClose,
  exposures,
}: {
  finding: ExposureFinding | null;
  onClose: () => void;
  exposures?: CorrelatedExposure[];
}) {
  const correlated = React.useMemo(
    () => (finding && exposures ? exposures.find((exposure) => exposure.findingIds.includes(finding.id)) : undefined),
    [finding, exposures],
  );

  return (
    <AnimatePresence>
      {finding && (
        <motion.div
          key="finding-detail"
          initial={{ opacity: 0 }}
          animate={{ opacity: 1 }}
          exit={{ opacity: 0 }}
          className="fixed inset-0 z-[70] flex justify-end bg-black/60 backdrop-blur-sm"
          onClick={onClose}
        >
          <motion.aside
            initial={{ x: 40, opacity: 0 }}
            animate={{ x: 0, opacity: 1 }}
            exit={{ x: 40, opacity: 0 }}
            transition={{ type: 'spring', stiffness: 320, damping: 34 }}
            role="dialog"
            aria-label="Finding detail"
            onClick={(event) => event.stopPropagation()}
            className="flex h-full w-full max-w-xl flex-col overflow-y-auto border-l border-white/[0.08] bg-[#060b16]"
          >
            <header className="sticky top-0 z-10 flex items-start justify-between gap-3 border-b border-white/[0.07] bg-[#060b16]/95 px-5 py-4 backdrop-blur">
              <div className="min-w-0">
                <div className="flex flex-wrap items-center gap-1.5">
                  <SeverityBadge severity={finding.severity} />
                  <ConfidenceBadge confidence={finding.confidence} detection={finding.detection} />
                  {finding.quantumStatus !== 'not-applicable' && <QuantumBadge status={finding.quantumStatus} />}
                </div>
                <h3 className="mt-2 text-[16px] font-black leading-tight text-white">{finding.title}</h3>
                <p className="mt-1 font-mono text-[10px] uppercase tracking-[0.14em] text-slate-500">
                  {layerLabel(finding.layer)} · {finding.category}
                  {finding.subcategory ? ` · ${finding.subcategory}` : ''}
                </p>
              </div>
              <button
                type="button"
                onClick={onClose}
                aria-label="Close"
                className="shrink-0 rounded-lg border border-white/[0.08] p-1.5 text-slate-400 transition-colors hover:text-white"
              >
                <X className="h-4 w-4" />
              </button>
            </header>

            <div className="space-y-5 px-5 py-5">
              <section>
                <p className="text-[12.5px] leading-relaxed text-slate-300">{finding.description}</p>
              </section>

              {(finding.canonicalAlgorithm || finding.role || finding.keySize || finding.library || finding.component) && (
                <section>
                  <h4 className="font-mono text-[9.5px] font-bold uppercase tracking-[0.18em] text-slate-500">Cryptographic subject</h4>
                  <dl className="mt-2 grid grid-cols-2 gap-2">
                    {finding.canonicalAlgorithm && <DetailCell label="Algorithm" value={finding.canonicalAlgorithm} />}
                    {finding.keySize ? <DetailCell label="Key size" value={`${finding.keySize} bits`} /> : null}
                    {finding.role && finding.role !== 'unknown' && <DetailCell label="Usage" value={finding.role.replace(/-/g, ' ')} />}
                    {finding.library && <DetailCell label="Library" value={finding.library} />}
                    {finding.component && <DetailCell label="Component" value={finding.component} />}
                    {finding.version && <DetailCell label="Version" value={finding.version} />}
                    {finding.protocol && <DetailCell label="Protocol" value={finding.protocol} />}
                  </dl>
                </section>
              )}

              {finding.quantumRationale && (
                <section className="rounded-xl border border-violet-400/20 bg-violet-400/[0.05] px-4 py-3">
                  <h4 className="flex items-center gap-1.5 font-mono text-[9.5px] font-bold uppercase tracking-[0.18em] text-violet-300">
                    <Sparkles className="h-3 w-3" /> Why this quantum verdict
                  </h4>
                  <p className="mt-1.5 text-[12px] leading-relaxed text-violet-100/85">{finding.quantumRationale}</p>
                </section>
              )}

              <section>
                <h4 className="font-mono text-[9.5px] font-bold uppercase tracking-[0.18em] text-slate-500">
                  Evidence ({finding.evidence.length})
                </h4>
                <ul className="mt-2 space-y-2">
                  {finding.evidence.map((entry, index) => (
                    <li key={index} className="rounded-xl border border-white/[0.07] bg-white/[0.02] px-3.5 py-3">
                      <p className="text-[12px] leading-snug text-slate-300">{entry.summary}</p>
                      <div className="mt-1.5 flex flex-wrap gap-x-3 gap-y-1 font-mono text-[10px] text-slate-500">
                        {entry.file && (
                          <span>
                            {entry.file}
                            {entry.line ? `:${entry.line}` : ''}
                          </span>
                        )}
                        {entry.reference && <span>{entry.reference}</span>}
                        {entry.provider && <span>{entry.provider}</span>}
                        {entry.ruleId && <span>rule {entry.ruleId}</span>}
                        {entry.localOnly && <span className="text-emerald-400/80">local-only</span>}
                      </div>
                      {entry.snippet && (
                        <pre className="mt-2 overflow-x-auto rounded-lg bg-[#040810] px-3 py-2 font-mono text-[10.5px] leading-relaxed text-slate-400">
                          {entry.snippet}
                        </pre>
                      )}
                      {entry.attributes && Object.keys(entry.attributes).length > 0 && (
                        <dl className="mt-2 grid grid-cols-2 gap-1.5">
                          {Object.entries(entry.attributes).slice(0, 10).map(([key, value]) => (
                            <div key={key} className="min-w-0">
                              <dt className="truncate font-mono text-[9px] uppercase tracking-wider text-slate-600">{key}</dt>
                              <dd className="truncate font-mono text-[10.5px] text-slate-400">{String(value)}</dd>
                            </div>
                          ))}
                        </dl>
                      )}
                    </li>
                  ))}
                </ul>
              </section>

              {correlated && correlated.findingIds.length > 1 && (
                <section className="rounded-xl border border-cyan-400/20 bg-cyan-400/[0.04] px-4 py-3">
                  <h4 className="font-mono text-[9.5px] font-bold uppercase tracking-[0.18em] text-cyan-300">Correlated exposure</h4>
                  <p className="mt-1.5 text-[12px] leading-relaxed text-cyan-100/85">
                    This finding is one of {correlated.findingIds.length} observations of the same underlying exposure, seen at{' '}
                    {correlated.layers.map(layerLabel).join(' → ')}.
                  </p>
                  {correlated.path && correlated.path.length > 1 && (
                    <ol className="mt-2.5 space-y-1">
                      {correlated.path.map((hop, index) => (
                        <li key={index} className="flex items-start gap-2 text-[11.5px] text-slate-300">
                          <span className="mt-1 h-1.5 w-1.5 shrink-0 rounded-full bg-cyan-400" />
                          <span>
                            <strong className="font-bold">{hop.label}</strong>
                            {hop.detail ? <span className="text-slate-500"> — {hop.detail}</span> : null}
                          </span>
                        </li>
                      ))}
                    </ol>
                  )}
                </section>
              )}

              {finding.recommendation && (
                <section className="rounded-xl border border-emerald-400/20 bg-emerald-400/[0.05] px-4 py-3">
                  <h4 className="font-mono text-[9.5px] font-bold uppercase tracking-[0.18em] text-emerald-300">Recommended action</h4>
                  <p className="mt-1.5 text-[12px] leading-relaxed text-emerald-100/85">{finding.recommendation}</p>
                </section>
              )}

              {finding.migration?.candidate && (
                <section className="rounded-xl border border-white/[0.08] bg-white/[0.02] px-4 py-3">
                  <h4 className="font-mono text-[9.5px] font-bold uppercase tracking-[0.18em] text-slate-400">Migration</h4>
                  <dl className="mt-2 grid grid-cols-2 gap-2">
                    {finding.migration.target && <DetailCell label="Target" value={finding.migration.target} />}
                    {finding.migration.priority && <DetailCell label="Priority" value={finding.migration.priority} />}
                    {finding.migration.complexity && <DetailCell label="Complexity" value={finding.migration.complexity} />}
                  </dl>
                  <p className="mt-2 text-[11px] leading-relaxed text-slate-500">
                    Scanning and remediation are separate workflows — this platform never modifies source, configuration or
                    infrastructure from an assessment.
                  </p>
                </section>
              )}

              <section className="flex items-center gap-2">
                <button
                  type="button"
                  onClick={() => {
                    void navigator.clipboard?.writeText(JSON.stringify(finding, null, 2));
                  }}
                  className="inline-flex items-center gap-1.5 rounded-lg border border-white/[0.08] px-3 py-1.5 text-[11.5px] font-semibold text-slate-300 transition-colors hover:border-cyan-400/30 hover:text-cyan-300"
                >
                  <Copy className="h-3.5 w-3.5" /> Copy finding JSON
                </button>
              </section>
            </div>
          </motion.aside>
        </motion.div>
      )}
    </AnimatePresence>
  );
}

function DetailCell({ label, value }: { label: string; value: string }) {
  return (
    <div className="min-w-0 rounded-lg border border-white/[0.06] bg-white/[0.02] px-2.5 py-1.5">
      <dt className="font-mono text-[9px] uppercase tracking-wider text-slate-600">{label}</dt>
      <dd className="truncate text-[12px] font-semibold text-slate-200" title={value}>
        {value}
      </dd>
    </div>
  );
}

/* ───────────────────────────────────────────────────────────── CBOM viewer ── */

export function CbomViewer({
  components,
  onExport,
}: {
  components: CbomComponent[];
  onExport?: (format: 'json' | 'csv' | 'cyclonedx') => void;
}) {
  const [limit, setLimit] = React.useState(40);
  const visible = components.slice(0, limit);

  return (
    <Panel className="overflow-hidden">
      <div className="flex flex-wrap items-center justify-between gap-3 border-b border-white/[0.06] px-5 py-3">
        <SectionLabel accent={ACCENT.emerald}>Cryptographic Bill of Materials</SectionLabel>
        <div className="flex flex-wrap items-center gap-1.5">
          <span className="font-mono text-[10px] text-slate-500">{components.length} components</span>
          {onExport && (
            <>
              <ExportButton icon={FileJson} label="JSON" onClick={() => onExport('json')} />
              <ExportButton icon={FileSpreadsheet} label="CSV" onClick={() => onExport('csv')} />
              <ExportButton icon={Download} label="CycloneDX" onClick={() => onExport('cyclonedx')} />
            </>
          )}
        </div>
      </div>

      {components.length === 0 ? (
        <p className="px-5 py-8 text-center text-[12px] text-slate-500">
          No cryptographic components were inventoried. A finding about a missing control is not a cryptographic component,
          so a scan can produce findings and an empty CBOM.
        </p>
      ) : (
        <div className="overflow-x-auto">
          <table className="w-full min-w-[52rem] border-collapse text-left">
            <thead>
              <tr className="border-b border-white/[0.06] font-mono text-[9.5px] uppercase tracking-[0.14em] text-slate-500">
                <th className="px-5 py-2 font-bold">Algorithm</th>
                <th className="px-3 py-2 font-bold">Usage</th>
                <th className="px-3 py-2 font-bold">Location</th>
                <th className="px-3 py-2 font-bold">Layer</th>
                <th className="px-3 py-2 font-bold">Detection</th>
                <th className="px-5 py-2 font-bold">Quantum</th>
              </tr>
            </thead>
            <tbody className="divide-y divide-white/[0.04]">
              {visible.map((component) => (
                <tr key={component.id} className="align-top">
                  <td className="px-5 py-2.5">
                    <p className="text-[12px] font-bold text-white">
                      {component.canonicalAlgorithm}
                      {component.keySize ? <span className="text-slate-500">-{component.keySize}</span> : null}
                    </p>
                    {component.library && <p className="font-mono text-[10px] text-slate-500">{component.library}</p>}
                  </td>
                  <td className="px-3 py-2.5 text-[11.5px] text-slate-300">{component.usage.replace(/-/g, ' ')}</td>
                  <td className="max-w-[16rem] px-3 py-2.5">
                    <p className="truncate font-mono text-[10.5px] text-slate-400" title={component.file ?? component.evidence[0]?.reference}>
                      {component.file ?? component.evidence[0]?.reference ?? '—'}
                      {component.line ? `:${component.line}` : ''}
                    </p>
                  </td>
                  <td className="px-3 py-2.5 font-mono text-[10.5px] text-slate-400">{layerLabel(component.layer)}</td>
                  <td className="px-3 py-2.5">
                    <ConfidenceBadge confidence={component.confidence} detection={component.detection} />
                  </td>
                  <td className="px-5 py-2.5">
                    <QuantumBadge status={component.quantumStatus} />
                  </td>
                </tr>
              ))}
            </tbody>
          </table>
        </div>
      )}

      {components.length > visible.length && (
        <button
          type="button"
          onClick={() => setLimit((current) => current + 60)}
          className="w-full border-t border-white/[0.06] px-5 py-2.5 text-[11.5px] font-semibold text-cyan-300 transition-colors hover:bg-cyan-400/[0.05]"
        >
          Show {Math.min(60, components.length - visible.length)} more of {components.length}
        </button>
      )}
    </Panel>
  );
}

function ExportButton({ icon: Icon, label, onClick }: { icon: typeof FileJson; label: string; onClick: () => void }) {
  return (
    <button
      type="button"
      onClick={onClick}
      className="inline-flex items-center gap-1 rounded-lg border border-white/[0.08] px-2 py-1 text-[10.5px] font-semibold text-slate-300 transition-colors hover:border-cyan-400/30 hover:text-cyan-300"
    >
      <Icon className="h-3 w-3" /> {label}
    </button>
  );
}

/* ─────────────────────────────────────────────────────────── coverage panel ── */

/**
 * Coverage and its limits (§41, Spec-2 §42-43).
 *
 * The "Not Assessed" list is the most important part of this panel and is
 * therefore rendered first among the qualifiers, not tucked at the bottom. A
 * reader who sees "0 critical findings" needs to see, in the same glance,
 * whether four dimensions were never read.
 */
export function CoveragePanel({ coverage, mode }: { coverage: ScanCoverage; mode: ScanMode }) {
  const metrics: Array<{ label: string; value: number }> = [
    { label: 'Files discovered', value: coverage.filesDiscovered },
    { label: 'Files analysed', value: coverage.filesAnalyzed },
    { label: 'Binary / unsupported', value: coverage.filesUnsupported },
    { label: 'Files skipped', value: coverage.filesSkipped },
    { label: 'Dependencies', value: coverage.dependencies },
    { label: 'Crypto components', value: coverage.cryptoComponents },
    { label: 'Certificates', value: coverage.certificates },
    { label: 'Secrets', value: coverage.secrets },
    { label: 'Config files', value: coverage.configFiles },
    { label: 'Containers', value: coverage.containers },
    { label: 'Images', value: coverage.images },
    { label: 'K8s namespaces', value: coverage.kubernetesNamespaces },
    { label: 'K8s workloads', value: coverage.kubernetesWorkloads },
    { label: 'IaC files', value: coverage.iacFiles },
    { label: 'CI/CD workflows', value: coverage.cicdWorkflows },
    { label: 'Cloud resources', value: coverage.cloudResources },
    { label: 'Branches', value: coverage.branches },
    { label: 'Commits analysed', value: coverage.commitsAnalyzed },
  ];

  /* A dimension the scan READ and found none of is a measurement; a dimension
     no engine reached is not. Hiding both behind `value > 0` rendered them
     identically, so "this repository has no Kubernetes" and "the Kubernetes
     engine never ran" looked the same (§43). Zeros stay, dimmed; the panel
     names the ones nothing reported separately. */
  const present = metrics.filter((metric) => metric.value > 0);
  const measuredZero = metrics.filter((metric) => metric.value === 0);

  return (
    <Panel className="overflow-hidden">
      <div className="flex flex-wrap items-center justify-between gap-2 border-b border-white/[0.06] px-5 py-3">
        <SectionLabel accent={ACCENT.amber}>Assessment Coverage</SectionLabel>
        <span className="font-mono text-[10px] text-slate-500">Across this assessment</span>
      </div>

      {coverage.notAssessed.length > 0 && (
        <div className="border-b border-white/[0.06] bg-amber-400/[0.05] px-5 py-3.5">
          <p className="flex items-center gap-1.5 font-mono text-[9.5px] font-bold uppercase tracking-[0.16em] text-amber-300">
            <AlertTriangle className="h-3 w-3" /> Not assessed ({coverage.notAssessed.length})
          </p>
          <ul className="mt-2 space-y-1.5">
            {coverage.notAssessed.map((entry, index) => (
              <li key={index} className="text-[11.5px] leading-relaxed text-amber-100/80">
                <strong className="font-bold">{entry.dimension}:</strong> {entry.reason}
              </li>
            ))}
          </ul>
          <p className="mt-2 text-[11px] italic text-amber-200/60">
            A dimension that could not be read is reported here, never as a passing control.
          </p>
        </div>
      )}

      {present.length > 0 && (
        <div className="grid grid-cols-2 gap-px bg-white/[0.05] sm:grid-cols-3 lg:grid-cols-4">
          {present.map((metric) => (
            <div key={metric.label} className="bg-[#080d1a] px-4 py-3">
              <p className="font-mono text-[9px] font-bold uppercase tracking-[0.14em] text-slate-500">{metric.label}</p>
              <p className="mt-0.5 font-mono text-[18px] font-black leading-none text-slate-200">{metric.value.toLocaleString()}</p>
            </div>
          ))}
        </div>
      )}

      {measuredZero.length > 0 && (
        <p className="border-t border-white/[0.06] px-5 py-2.5 text-[11px] leading-relaxed text-slate-500">
          <span className="font-mono text-[9.5px] font-bold uppercase tracking-[0.16em] text-slate-400">Read, none found:</span>{' '}
          {measuredZero.map((metric) => metric.label).join(', ')}. These are measurements of zero, not dimensions that went
          unread — anything the scan could not reach is listed under Not assessed above.
        </p>
      )}

      {coverage.exclusions.length > 0 && (
        <div className="border-t border-white/[0.06] px-5 py-3">
          <p className="font-mono text-[9.5px] font-bold uppercase tracking-[0.16em] text-slate-500">Exclusions in force</p>
          <ul className="mt-1.5 space-y-1">
            {coverage.exclusions.map((exclusion, index) => (
              <li key={index} className="text-[11px] leading-relaxed text-slate-500">
                {exclusion}
              </li>
            ))}
          </ul>
        </div>
      )}

      {coverage.truncated && coverage.truncationNote && (
        <p className="border-t border-white/[0.06] bg-white/[0.015] px-5 py-2.5 text-[11.5px] leading-relaxed text-slate-400">
          <Info aria-hidden className="mr-1.5 inline h-3 w-3 -translate-y-px text-slate-500" />
          {coverage.truncationNote}
        </p>
      )}

      <p className="border-t border-white/[0.06] px-5 py-2.5 text-[11px] leading-relaxed text-slate-500">
        {mode === 'local'
          ? 'Local processing: every file above was read on this device and analysed in this browser tab. No file content, secret value or Git object was transmitted.'
          : 'Read-only assessment: no repository, cluster, cloud account or registry was modified, and no repository code was executed.'}
      </p>
    </Panel>
  );
}

/* ──────────────────────────────────────────────────── correlated exposures ── */

/** Rows rendered before the list is capped. Stated to the reader below. */
const CORRELATED_LIMIT = 25;

export function CorrelatedExposures({ exposures }: { exposures: CorrelatedExposure[] }) {
  const [open, setOpen] = React.useState<string | null>(null);
  const multi = exposures.filter((exposure) => exposure.findingIds.length > 1 || (exposure.layers.length > 1));

  if (multi.length === 0) return null;

  return (
    <Panel className="overflow-hidden">
      <div className="flex items-center justify-between gap-3 border-b border-white/[0.06] px-5 py-3">
        <SectionLabel accent={ACCENT.violet}>Correlated Exposures</SectionLabel>
        <span className="font-mono text-[10px] text-slate-500">{multi.length} spanning multiple layers</span>
      </div>
      <p className="border-b border-white/[0.06] px-5 py-2.5 text-[11.5px] leading-relaxed text-slate-400">
        Findings that describe the same underlying exposure are merged into one row with all of their evidence sources,
        rather than repeated once per engine that saw them.
      </p>
      <ul className="divide-y divide-white/[0.04]">
        {multi.slice(0, CORRELATED_LIMIT).map((exposure) => {
          const expanded = open === exposure.key;
          return (
            <li key={exposure.key}>
              <button
                type="button"
                onClick={() => setOpen(expanded ? null : exposure.key)}
                aria-expanded={expanded}
                className="flex w-full items-start gap-3 px-5 py-3 text-left transition-colors hover:bg-white/[0.02]"
              >
                <span aria-hidden className="mt-1.5 h-2 w-2 shrink-0 rounded-full" style={{ backgroundColor: SEVERITY_COLOR[exposure.severity] }} />
                <span className="min-w-0 flex-1">
                  <span className="flex flex-wrap items-center gap-1.5">
                    <span className="text-[12.5px] font-bold text-white">{exposure.title}</span>
                    <SeverityBadge severity={exposure.severity} />
                    <ConfidenceBadge confidence={exposure.confidence} />
                    <QuantumBadge status={exposure.quantumStatus} />
                  </span>
                  <span className="mt-1 block font-mono text-[10.5px] text-slate-500">
                    {exposure.layers.map(layerLabel).join(' → ')} · {exposure.evidence.length} evidence source
                    {exposure.evidence.length === 1 ? '' : 's'}
                  </span>
                </span>
                <ChevronDown aria-hidden className={cn('mt-1 h-4 w-4 shrink-0 text-slate-600 transition-transform', expanded && 'rotate-180')} />
              </button>

              <AnimatePresence initial={false}>
                {expanded && (
                  <motion.div
                    initial={{ height: 0, opacity: 0 }}
                    animate={{ height: 'auto', opacity: 1 }}
                    exit={{ height: 0, opacity: 0 }}
                    transition={{ duration: 0.25 }}
                    className="overflow-hidden"
                  >
                    <div className="space-y-2 px-5 pb-4">
                      {exposure.path && exposure.path.length > 1 && (
                        <ol className="flex flex-wrap items-center gap-1.5">
                          {exposure.path.map((hop, index) => (
                            <React.Fragment key={index}>
                              {index > 0 && <ChevronRight aria-hidden className="h-3 w-3 text-slate-700" />}
                              <li
                                className="rounded-lg border border-cyan-400/20 bg-cyan-400/[0.05] px-2 py-1 text-[10.5px] text-cyan-200"
                                title={hop.detail}
                              >
                                {hop.label}
                              </li>
                            </React.Fragment>
                          ))}
                        </ol>
                      )}
                      <ul className="space-y-1.5">
                        {exposure.evidence.slice(0, 8).map((entry, index) => (
                          <li key={index} className="rounded-lg border border-white/[0.06] bg-white/[0.02] px-3 py-2">
                            <p className="text-[11.5px] leading-snug text-slate-300">{entry.summary}</p>
                            {(entry.file || entry.reference) && (
                              <p className="mt-0.5 truncate font-mono text-[10px] text-slate-500">
                                {entry.file ?? entry.reference}
                                {entry.line ? `:${entry.line}` : ''}
                              </p>
                            )}
                          </li>
                        ))}
                      </ul>
                      {exposure.recommendation && (
                        <p className="rounded-lg border border-emerald-400/20 bg-emerald-400/[0.05] px-3 py-2 text-[11.5px] leading-relaxed text-emerald-100/85">
                          {exposure.recommendation}
                        </p>
                      )}
                    </div>
                  </motion.div>
                )}
              </AnimatePresence>
            </li>
          );
        })}
      </ul>
      <ListTruncationNote
        shown={CORRELATED_LIMIT}
        total={multi.length}
        noun="exposures spanning multiple layers"
        rank="widest-spanning"
      />
    </Panel>
  );
}

/* ───────────────────────────────────────────────────────── recommendations ── */

export function ExposureRecommendations({ assessment }: { assessment: ExposureAssessment }) {
  const { recommendations } = assessment.intelligence;
  if (recommendations.length === 0) return null;

  return (
    <Panel className="overflow-hidden">
      <div className="border-b border-white/[0.06] px-5 py-3">
        <SectionLabel accent={ACCENT.emerald}>Recommended Actions</SectionLabel>
      </div>
      <ol className="divide-y divide-white/[0.04]">
        {recommendations.map((recommendation, index) => (
          <li key={index} className="flex items-start gap-3 px-5 py-3">
            <span
              aria-hidden
              className="mt-0.5 grid h-6 w-6 shrink-0 place-items-center rounded-full font-mono text-[11px] font-black"
              style={{ backgroundColor: `${SEVERITY_COLOR[recommendation.severity]}18`, color: SEVERITY_COLOR[recommendation.severity] }}
            >
              {index + 1}
            </span>
            <div className="min-w-0 flex-1">
              <p className="text-[12.5px] font-bold text-white">{recommendation.title}</p>
              <p className="mt-0.5 text-[11.5px] leading-relaxed text-slate-400">{recommendation.detail}</p>
            </div>
            <span className="mt-0.5 shrink-0 rounded bg-white/[0.06] px-1.5 py-0.5 font-mono text-[9px] uppercase tracking-widest text-slate-400">
              {recommendation.effort} effort
            </span>
          </li>
        ))}
      </ol>
    </Panel>
  );
}

/* ───────────────────────────────────────────────────────────── status bar ─── */

export function AssessmentStatusBar({
  assessment,
  onReset,
  onSync,
  syncState,
  extra,
}: {
  assessment: ExposureAssessment;
  onReset?: () => void;
  onSync?: () => void;
  syncState?: 'idle' | 'syncing' | 'synced' | 'error';
  extra?: React.ReactNode;
}) {
  const { task } = assessment;
  const partial = task.status === 'partial';
  const cancelled = task.status === 'cancelled';

  return (
    <Panel className="flex flex-wrap items-center justify-between gap-3 px-5 py-3">
      <div className="flex min-w-0 items-center gap-2.5">
        {partial || cancelled ? (
          <ShieldAlert className={cn('h-4 w-4 shrink-0', cancelled ? 'text-slate-400' : 'text-amber-400')} />
        ) : (
          <ShieldCheck className="h-4 w-4 shrink-0 text-emerald-400" />
        )}
        <span className="text-[13.5px] font-bold text-white">
          {cancelled ? 'Assessment cancelled' : partial ? 'Assessment completed with gaps' : 'Assessment complete'}
        </span>
        <span className="truncate text-[12px] text-slate-500">
          {assessment.findings.length} finding{assessment.findings.length === 1 ? '' : 's'} ·{' '}
          {assessment.exposures.length} correlated exposure{assessment.exposures.length === 1 ? '' : 's'} ·{' '}
          {assessment.cbom.length} cryptographic component{assessment.cbom.length === 1 ? '' : 's'}
        </span>
      </div>
      <div className="flex flex-wrap items-center gap-2">
        {extra}
        {onSync && (
          <button
            type="button"
            onClick={onSync}
            disabled={syncState === 'syncing' || syncState === 'synced'}
            className="inline-flex items-center gap-1.5 rounded-lg border border-cyan-400/25 bg-cyan-400/[0.06] px-3 py-1.5 text-[11.5px] font-bold text-cyan-300 transition-colors hover:bg-cyan-400/[0.12] disabled:opacity-50"
          >
            {syncState === 'syncing' ? <Loader2 className="h-3.5 w-3.5 animate-spin" /> : <Check className="h-3.5 w-3.5" />}
            {syncState === 'synced' ? 'Synchronized' : syncState === 'syncing' ? 'Synchronizing' : 'Sync to platform'}
          </button>
        )}
        {onReset && (
          <button
            type="button"
            onClick={onReset}
            className="inline-flex items-center gap-1.5 rounded-lg border border-white/[0.08] px-3 py-1.5 text-[11.5px] font-semibold text-slate-400 transition-colors hover:text-white"
          >
            New assessment
          </button>
        )}
      </div>
      {partial && task.failureReason && (
        <p className="w-full border-t border-white/[0.06] pt-2.5 text-[11.5px] leading-relaxed text-amber-100/80">
          <strong className="font-bold">Partial coverage.</strong> {task.failureReason} Scores are computed only from the
          engines that reported.
        </p>
      )}
    </Panel>
  );
}
