/**
 * Quantum Simulation Range — the three laboratories.
 *
 *   Shor Laboratory      run the real state-vector simulator and factor a number
 *   Resource Estimator   what a CRQC would actually cost, per published model
 *   Mosca Calculator     X + Y > Z — am I already too late?
 *
 * These are the panels that answer "how does this actually work" rather than
 * "what happens". The Shor lab in particular is the reason this page can claim
 * to be a simulation at all: every plot in it is drawn from a Float64Array that
 * a quantum circuit produced, not from an easing curve.
 */

import React from 'react';
import { motion } from 'framer-motion';
import { AlertTriangle, Cpu, Play } from 'lucide-react';
import {
  ANCHOR_HARDWARE,
  REPORTED_DEVICES,
  SHELF_LIFE_PRESETS,
  SHOR_TARGETS,
  crqcEstimates,
  estimateEcc,
  estimateRsa,
  evaluateMosca,
  formatCount,
  formatDuration,
  modPow,
  runShor,
  simulationWall,
  type EstimatorModel,
  type ResourceEstimate,
  type ShorResult,
} from '@/lib/quantum-sim';
import { QSR, tint } from '../_theme';
import { ActionButton, Callout, Chip, Cite, DataRow, LogBar, Panel, ProvenanceBadge, Segmented, Slider, StatTile } from '../_ui';

/* ═══════════════════════════════════════════════════════════════ mini charts */

/**
 * The measurement distribution, drawn on a canvas because a 4,096-bin bar chart
 * is 4,096 DOM nodes in SVG and one draw call here.
 */
function DistributionChart({
  distribution,
  accent,
  peakMarkers,
  measured,
  height = 150,
}: {
  distribution: Float64Array;
  accent: string;
  /** Fractions k/r where the comb teeth should be, when the order is known. */
  peakMarkers: number[];
  /** The single outcome this shot measured, as a fraction of 2^t. */
  measured: number | null;
  height?: number;
}) {
  const canvas = React.useRef<HTMLCanvasElement>(null);

  React.useEffect(() => {
    const element = canvas.current;
    if (!element) return;
    const ratio = Math.min(2, window.devicePixelRatio || 1);
    const width = element.clientWidth;
    element.width = width * ratio;
    element.height = height * ratio;
    const ctx = element.getContext('2d');
    if (!ctx) return;
    ctx.scale(ratio, ratio);
    ctx.clearRect(0, 0, width, height);

    let peak = 0;
    for (let i = 0; i < distribution.length; i += 1) peak = Math.max(peak, distribution[i]);
    if (peak <= 0) peak = 1;

    // Comb markers first, so the data draws over them.
    ctx.strokeStyle = tint(QSR.quantum, 0.45);
    ctx.setLineDash([3, 4]);
    ctx.lineWidth = 1;
    for (const fraction of peakMarkers) {
      const x = fraction * width;
      ctx.beginPath();
      ctx.moveTo(x, 0);
      ctx.lineTo(x, height);
      ctx.stroke();
    }
    ctx.setLineDash([]);

    // The distribution. One column per pixel, taking the max in each bucket so
    // a sharp peak is never averaged away by downsampling.
    const perPixel = distribution.length / width;
    const gradient = ctx.createLinearGradient(0, 0, 0, height);
    gradient.addColorStop(0, accent);
    gradient.addColorStop(1, tint(accent, 0.12));
    ctx.fillStyle = gradient;
    for (let x = 0; x < width; x += 1) {
      let value = 0;
      const start = Math.floor(x * perPixel);
      const end = Math.max(start + 1, Math.floor((x + 1) * perPixel));
      for (let i = start; i < end && i < distribution.length; i += 1) value = Math.max(value, distribution[i]);
      const barHeight = (value / peak) * (height - 8);
      if (barHeight > 0.4) ctx.fillRect(x, height - barHeight, 1, barHeight);
    }

    if (measured !== null) {
      ctx.strokeStyle = QSR.broken;
      ctx.lineWidth = 1.5;
      const x = measured * width;
      ctx.beginPath();
      ctx.moveTo(x, 0);
      ctx.lineTo(x, height);
      ctx.stroke();
    }
  }, [distribution, accent, peakMarkers, measured, height]);

  return <canvas ref={canvas} className="w-full" style={{ height }} />;
}

/**
 * a^x mod N — the classical periodic function the quantum register encodes.
 *
 * Only a handful of periods are drawn. Plotting all 2^t samples aliases the
 * repetition into noise at any sane chart width, which hides the single thing
 * the chart exists to show.
 */
function PeriodicFunctionChart({ values, period, accent }: { values: number[]; period: number | null; accent: string }) {
  const window = period ? Math.min(values.length, Math.max(period * 6, 24)) : Math.min(values.length, 64);
  const shown = values.slice(0, window);
  const max = Math.max(1, ...shown);
  const barWidth = 0.7;

  return (
    <svg viewBox={`0 0 ${window} 46`} preserveAspectRatio="none" className="h-[46px] w-full">
      {period !== null &&
        Array.from({ length: Math.ceil(window / period) }, (_, i) => (
          <rect key={i} x={i * period} y={0} width={period} height={46} fill={i % 2 === 0 ? tint(accent, 0.09) : 'transparent'} />
        ))}
      {shown.map((value, index) => (
        <rect
          key={index}
          x={index + (1 - barWidth) / 2}
          y={46 - (value / max) * 42}
          width={barWidth}
          height={Math.max(1, (value / max) * 42)}
          fill={accent}
          opacity={0.9}
        />
      ))}
    </svg>
  );
}

/* ═══════════════════════════════════════════════════════════════ Shor lab */

export interface ShorLabProps {
  onResult: (result: ShorResult) => void;
  /** Deferred until the section scrolls into view — the simulator is not cheap. */
  active: boolean;
}

export function ShorLab({ onResult, active }: ShorLabProps) {
  const [targetN, setTargetN] = React.useState(15);
  const [base, setBase] = React.useState<number | 'auto'>('auto');
  const [controlQubits, setControlQubits] = React.useState<number | 'auto'>('auto');
  const [result, setResult] = React.useState<ShorResult | null>(null);
  const [error, setError] = React.useState<string | null>(null);
  const [busy, setBusy] = React.useState(false);
  const [shots, setShots] = React.useState(0);
  const seed = React.useRef(0xc0ffee);

  const target = SHOR_TARGETS.find((t) => t.N === targetN) ?? SHOR_TARGETS[0];
  const workQubits = Math.ceil(Math.log2(targetN));
  const effectiveControl = controlQubits === 'auto' ? 2 * workQubits : controlQubits;

  const run = React.useCallback(() => {
    setBusy(true);
    setError(null);
    // Yield to paint: the simulator blocks the main thread for tens of ms, so
    // the button must show its busy state first or the page looks frozen. This
    // is a timer rather than a rAF because rAF never fires in a background tab
    // or a non-compositing embed, which would strand the panel on "Running".
    setTimeout(() => {
      try {
        seed.current = (seed.current * 1664525 + 1013904223) >>> 0;
        const next = runShor({
          N: targetN,
          a: base === 'auto' ? undefined : base,
          controlQubits: controlQubits === 'auto' ? undefined : controlQubits,
          seed: seed.current,
        });
        setResult(next);
        setShots((value) => value + 1);
        onResult(next);
      } catch (caught) {
        setError(caught instanceof Error ? caught.message : String(caught));
      } finally {
        setBusy(false);
      }
    });
  }, [base, controlQubits, onResult, targetN]);

  // First run once the panel is actually on screen.
  React.useEffect(() => {
    if (active && !result && !busy) run();
    // eslint-disable-next-line react-hooks/exhaustive-deps
  }, [active]);

  const combMarkers = React.useMemo(() => {
    if (!result?.trueOrder) return [];
    return Array.from({ length: result.trueOrder }, (_, k) => k / result.trueOrder);
  }, [result]);

  const wall = simulationWall(2048);

  return (
    <Panel
      accent={QSR.quantum}
      eyebrow="Laboratory 01 · state-vector simulator"
      title="Shor's Laboratory"
      subtitle={
        <>
          A genuine quantum circuit, executed here: Hadamards, controlled modular exponentiation, an inverse QFT, and a
          Born-rule measurement. The inverse QFT is verified against its closed-form definition by the offline check tool.{' '}
          <Cite source="shor1997" inline />
        </>
      }
      right={<ProvenanceBadge kind="measured" />}
    >
      <div className="grid gap-4 xl:grid-cols-[300px_minmax(0,1fr)]">
        {/* ── Controls ─────────────────────────────────────────────── */}
        <div className="space-y-4">
          <div>
            <span className="mb-1.5 block font-mono text-[9px] font-bold uppercase tracking-[0.18em]" style={{ color: QSR.inkMuted }}>
              Composite to factor
            </span>
            <div className="flex flex-wrap gap-1.5">
              {SHOR_TARGETS.map((option) => (
                <button
                  key={option.N}
                  type="button"
                  onClick={() => {
                    setTargetN(option.N);
                    setResult(null);
                    setShots(0);
                  }}
                  title={option.note}
                  className="rounded-md border px-2 py-1 font-mono text-[11px] font-bold transition-colors"
                  style={{
                    borderColor: option.N === targetN ? tint(QSR.quantum, 0.5) : QSR.hairline,
                    background: option.N === targetN ? tint(QSR.quantum, 0.14) : 'rgba(4,7,16,0.5)',
                    color: option.N === targetN ? QSR.quantum : QSR.inkMuted,
                  }}
                >
                  {option.N}
                </button>
              ))}
            </div>
            <p className="mt-1.5 text-[10.5px] leading-snug" style={{ color: QSR.inkFaint }}>
              {target.note}
            </p>
          </div>

          <div>
            <span className="mb-1.5 block font-mono text-[9px] font-bold uppercase tracking-[0.18em]" style={{ color: QSR.inkMuted }}>
              Base a
            </span>
            <Segmented
              size="sm"
              accent={QSR.quantum}
              value={base}
              onChange={(value) => {
                setBase(value);
                setResult(null);
              }}
              options={[
                { value: 'auto' as const, label: 'random', title: 'Draw a new coprime base each shot, as the real algorithm does' },
                ...[2, 3, 4, 5, 7]
                  .filter((candidate) => candidate < targetN)
                  .map((candidate) => ({ value: candidate, label: String(candidate) })),
              ]}
            />
          </div>

          <Slider
            label="Control qubits (t)"
            accent={QSR.quantum}
            min={workQubits}
            max={Math.min(2 * workQubits + 2, 22 - workQubits)}
            value={effectiveControl}
            onChange={(value) => setControlQubits(value)}
            format={(value) => `${value} (2n = ${2 * workQubits})`}
            hint="Lower t blurs the peaks until continued fractions can no longer resolve the period. This is the phase-estimation precision, and it is the most instructive control on the page."
          />

          <div className="rounded-lg border p-3" style={{ borderColor: QSR.hairline, background: 'rgba(4,7,16,0.5)' }}>
            <DataRow label="Work register" value={`${workQubits} qubits`} />
            <DataRow label="Control register" value={`${effectiveControl} qubits`} />
            <DataRow label="State vector" value={`2^${workQubits + effectiveControl} = ${(2 ** (workQubits + effectiveControl)).toLocaleString()}`} accent={QSR.live} />
            <DataRow label="Heap" value={`${(((2 ** (workQubits + effectiveControl)) * 16) / 1e6).toFixed(1)} MB`} />
          </div>

          <div className="flex flex-wrap items-center gap-2">
            <ActionButton onClick={run} busy={busy} accent={QSR.quantum}>
              <Play className="h-3.5 w-3.5" /> Run one shot
            </ActionButton>
            {shots > 0 && (
              <span className="font-mono text-[10px]" style={{ color: QSR.inkFaint }}>
                shot {shots}
              </span>
            )}
          </div>

          {error && (
            <Callout tone="danger" title="Cannot run">
              {error}
            </Callout>
          )}
        </div>

        {/* ── Results ──────────────────────────────────────────────── */}
        <div className="min-w-0 space-y-4">
          {result && (
            <>
              <div className="grid gap-2.5 sm:grid-cols-4">
                <StatTile label="Gates executed" value={result.gates.total.toLocaleString()} provenance="measured" accent={QSR.live} note={`${result.gates.modularMultiply} modular multiplications`} />
                <StatTile label="True order of a" value={result.trueOrder ?? '—'} provenance="measured" accent={QSR.quantum} note={`a = ${result.a}`} />
                <StatTile label="Measured y" value={result.measurement} provenance="measured" accent={QSR.broken} note={`φ = ${result.measuredPhase.toFixed(5)}`} />
                <StatTile
                  label="Factors"
                  value={result.factors ? `${result.factors[0]} × ${result.factors[1]}` : 'none'}
                  provenance="measured"
                  accent={result.factors ? QSR.safe : QSR.inkMuted}
                  note={`${result.elapsedMs.toFixed(1)} ms`}
                />
              </div>

              {/* The classical function the register encodes */}
              {result.periodicFunction.length > 0 && (
                <div className="rounded-lg border p-3" style={{ borderColor: QSR.hairline, background: 'rgba(4,7,16,0.5)' }}>
                  <div className="mb-1.5 flex items-center justify-between">
                    <span className="font-mono text-[9px] font-bold uppercase tracking-[0.18em]" style={{ color: QSR.inkMuted }}>
                      {result.a}<sup>x</sup> mod {result.N} — the hidden period
                    </span>
                    <span className="font-mono text-[9.5px]" style={{ color: QSR.quantum }}>
                      {result.trueOrder ? `repeats every ${result.trueOrder} — ${Math.ceil(Math.min(result.periodicFunction.length, Math.max(result.trueOrder * 6, 24)) / result.trueOrder)} periods shown` : 'aperiodic'}
                    </span>
                  </div>
                  <PeriodicFunctionChart values={result.periodicFunction} period={result.trueOrder} accent={QSR.live} />
                  <p className="mt-1.5 text-[10.5px] leading-snug" style={{ color: QSR.inkFaint }}>
                    A classical computer can plot this only because N is tiny. For RSA-2048 the period is astronomically large and
                    finding it by sampling is hopeless — that is the problem Shor's interference solves.
                  </p>
                </div>
              )}

              {/* The Born-rule distribution */}
              <div className="rounded-lg border p-3" style={{ borderColor: tint(QSR.quantum, 0.24), background: 'rgba(4,7,16,0.6)' }}>
                <div className="mb-1.5 flex flex-wrap items-center justify-between gap-2">
                  <span className="font-mono text-[9px] font-bold uppercase tracking-[0.18em]" style={{ color: QSR.quantum }}>
                    |ψ|² over the control register after the inverse QFT
                  </span>
                  <span className="flex items-center gap-2.5 font-mono text-[9px]" style={{ color: QSR.inkFaint }}>
                    <span className="flex items-center gap-1">
                      <span className="inline-block h-2 w-2" style={{ background: QSR.quantum }} /> comb at k/r
                    </span>
                    <span className="flex items-center gap-1">
                      <span className="inline-block h-2 w-[2px]" style={{ background: QSR.broken }} /> measured
                    </span>
                  </span>
                </div>
                <DistributionChart distribution={result.distribution} accent={QSR.live} peakMarkers={combMarkers} measured={result.measuredPhase} />
                <p className="mt-1.5 text-[10.5px] leading-snug" style={{ color: QSR.inkFaint }}>
                  Every outcome not close to a multiple of 2<sup>t</sup>/r cancelled. The peaks are what survived — this is
                  interference doing the work, not search.
                </p>
              </div>

              {/* The classical post-processing */}
              <div className="grid gap-3 lg:grid-cols-2">
                <div className="rounded-lg border p-3" style={{ borderColor: QSR.hairline, background: 'rgba(4,7,16,0.5)' }}>
                  <div className="mb-2 font-mono text-[9px] font-bold uppercase tracking-[0.18em]" style={{ color: QSR.inkMuted }}>
                    Continued fractions on {result.measurement}/{2 ** result.controlQubits}
                  </div>
                  {result.convergents.length === 0 ? (
                    <p className="text-[11px]" style={{ color: QSR.inkFaint }}>
                      No convergents below N. This shot yields nothing.
                    </p>
                  ) : (
                    <table className="w-full font-mono text-[10.5px]">
                      <thead>
                        <tr style={{ color: QSR.inkFaint }}>
                          <th className="pb-1 text-left font-normal">term</th>
                          <th className="pb-1 text-left font-normal">p/q</th>
                          <th className="pb-1 text-right font-normal">a^q mod N</th>
                        </tr>
                      </thead>
                      <tbody>
                        {result.convergents.map((convergent, index) => {
                          const check = modPow(result.a, convergent.denominator, result.N);
                          const hit = convergent.denominator === result.recoveredPeriod;
                          return (
                            <tr key={index} style={{ color: hit ? QSR.safe : QSR.inkSoft }}>
                              <td className="py-0.5">{convergent.term}</td>
                              <td className="py-0.5">
                                {convergent.numerator}/{convergent.denominator}
                              </td>
                              <td className="py-0.5 text-right">{check}{hit ? ' ✓' : ''}</td>
                            </tr>
                          );
                        })}
                      </tbody>
                    </table>
                  )}
                </div>

                <div className="space-y-2.5">
                  {result.success ? (
                    <Callout tone="good" title="Factored">
                      {result.stages[result.stages.length - 1].detail}
                    </Callout>
                  ) : (
                    <Callout tone="warn" title="This shot failed — and that is the algorithm working">
                      {result.failureReason}
                    </Callout>
                  )}
                  <div className="rounded-lg border p-3" style={{ borderColor: QSR.hairline, background: 'rgba(4,7,16,0.5)' }}>
                    <DataRow label="Hadamard gates" value={result.gates.hadamard} />
                    <DataRow label="Controlled phase" value={result.gates.controlledPhase} />
                    <DataRow label="Modular multiplications" value={result.gates.modularMultiply} accent={QSR.quantum} />
                    <DataRow label="Amplitudes held" value={(result.stateVectorBytes / 16).toLocaleString()} />
                  </div>
                </div>
              </div>

              {/* The stepper */}
              <div className="rounded-lg border p-3.5" style={{ borderColor: QSR.hairline, background: 'rgba(4,7,16,0.5)' }}>
                <div className="mb-2.5 font-mono text-[9px] font-bold uppercase tracking-[0.18em]" style={{ color: QSR.inkMuted }}>
                  What the circuit did, step by step
                </div>
                <ol className="space-y-2.5">
                  {result.stages.map((stage, index) => (
                    <li key={stage.id} className="flex gap-3">
                      <span
                        className="mt-0.5 flex h-5 w-5 shrink-0 items-center justify-center rounded-full font-mono text-[9px] font-bold"
                        style={{ background: tint(QSR.quantum, 0.18), color: QSR.quantum }}
                      >
                        {index + 1}
                      </span>
                      <div className="min-w-0">
                        <div className="text-[12px] font-semibold text-slate-100">{stage.title}</div>
                        <p className="mt-0.5 text-[11.5px] leading-relaxed" style={{ color: QSR.inkSoft }}>
                          {stage.detail}
                        </p>
                        <div className="mt-0.5 font-mono text-[10px]" style={{ color: QSR.inkFaint }}>
                          register: {stage.registerState}
                        </div>
                      </div>
                    </li>
                  ))}
                </ol>
              </div>
            </>
          )}

          <Callout tone="warn" title="Why this stops at two-digit numbers">
            <span className="flex items-start gap-2">
              <AlertTriangle className="mt-0.5 h-3.5 w-3.5 shrink-0" style={{ color: QSR.model }} />
              <span>
                Simulating m qubits costs 2<sup>m</sup> complex amplitudes. RSA-2048 needs about {wall.qubits.toLocaleString()}{' '}
                logical qubits, so its state vector would hold 10<sup>{Math.round(wall.amplitudesLog10)}</sup> numbers.{' '}
                {wall.comparison} That impossibility is the entire argument: no classical machine can fake a quantum computer, which
                is exactly why building one changes the situation.
              </span>
            </span>
          </Callout>
        </div>
      </div>
    </Panel>
  );
}

/* ═══════════════════════════════════════════════════════ resource estimator */

function EstimateColumn({ estimate, label }: { estimate: ResourceEstimate; label: string }) {
  if (estimate.infeasible) {
    return (
      <div className="rounded-lg border p-3.5" style={{ borderColor: tint(QSR.safe, 0.25), background: tint(QSR.safe, 0.05) }}>
        <div className="font-mono text-[9px] font-bold uppercase tracking-[0.18em]" style={{ color: QSR.safe }}>
          {label}
        </div>
        <div className="mt-1.5 text-[14px] font-bold" style={{ color: QSR.safe }}>
          Not achievable
        </div>
        <p className="mt-1.5 text-[11px] leading-snug" style={{ color: QSR.inkSoft }}>
          {estimate.infeasibleReason}
        </p>
      </div>
    );
  }

  return (
    <div className="rounded-lg border p-3.5" style={{ borderColor: QSR.hairline, background: 'rgba(4,7,16,0.55)' }}>
      <div className="flex items-center justify-between">
        <span className="font-mono text-[9px] font-bold uppercase tracking-[0.18em]" style={{ color: QSR.model }}>
          {label}
        </span>
        <Cite source={estimate.citation} />
      </div>
      <div className="mt-2 space-y-2">
        <div>
          <div className="flex items-baseline justify-between">
            <span className="font-mono text-[9px] uppercase tracking-[0.14em]" style={{ color: QSR.inkFaint }}>
              physical qubits
            </span>
            <span className="font-mono text-[17px] font-bold" style={{ color: QSR.model }}>
              {formatCount(estimate.physicalQubits)}
            </span>
          </div>
          <LogBar value={estimate.physicalQubits} floorLog10={2} ceilLog10={9} accent={QSR.model} />
        </div>
        <div>
          <div className="flex items-baseline justify-between">
            <span className="font-mono text-[9px] uppercase tracking-[0.14em]" style={{ color: QSR.inkFaint }}>
              wall clock
            </span>
            <span className="font-mono text-[17px] font-bold" style={{ color: QSR.broken }}>
              {formatDuration(estimate.runtimeSeconds)}
            </span>
          </div>
          <LogBar value={estimate.runtimeSeconds} floorLog10={0} ceilLog10={9} accent={QSR.broken} />
        </div>
      </div>
      <div className="mt-2.5 space-y-0">
        <DataRow label="Logical qubits" value={estimate.logical.qubits.toLocaleString()} />
        <DataRow label="Toffoli gates" value={formatCount(estimate.logical.toffoli)} />
        <DataRow label="Code distance d" value={estimate.codeDistance} />
        <DataRow label="Logical error / round" value={estimate.logicalErrorPerRound.toExponential(1)} />
      </div>
      <div className="mt-2 font-mono text-[9.5px] leading-snug" style={{ color: QSR.inkFaint }}>
        {estimate.logical.formula}
      </div>
    </div>
  );
}

export function ResourceEstimatorLab() {
  const [errorRate, setErrorRate] = React.useState(3); // index into ERROR_RATES
  const [cycleNs, setCycleNs] = React.useState(1000);
  const [model, setModel] = React.useState<EstimatorModel>('gidney-ekera-2021');
  const [rsaBits, setRsaBits] = React.useState(2048);

  const ERROR_RATES = [1e-5, 5e-5, 1e-4, 1e-3, 3e-3, 1e-2];
  const hardware = {
    physicalErrorRate: ERROR_RATES[errorRate],
    cycleTimeSeconds: cycleNs / 1e9,
    errorBudget: ANCHOR_HARDWARE.errorBudget,
  };

  const rsa = React.useMemo(
    () => estimateRsa(rsaBits, hardware, model === 'gidney-2025' ? 'gidney-2025' : 'gidney-ekera-2021'),
    [rsaBits, hardware.physicalErrorRate, hardware.cycleTimeSeconds, model],
  );
  const ecc = React.useMemo(() => estimateEcc(256, hardware), [hardware.physicalErrorRate, hardware.cycleTimeSeconds]);
  const largestDevice = REPORTED_DEVICES.reduce((best, device) => (device.qubits > best.qubits ? device : best));

  const gap = rsa.infeasible ? null : rsa.physicalQubits / largestDevice.qubits;

  return (
    <Panel
      accent={QSR.model}
      eyebrow="Laboratory 02 · surface-code resource model"
      title="What would a CRQC actually cost?"
      subtitle={
        <>
          Three published models, reproducing their own headline results. Move the hardware assumptions and watch the answer move
          — because "when is Q-Day" is a question about engineering budgets, not about mathematics.
        </>
      }
      right={<ProvenanceBadge kind="model" />}
    >
      <div className="grid gap-4 xl:grid-cols-[300px_minmax(0,1fr)]">
        <div className="space-y-4">
          <div>
            <span className="mb-1.5 block font-mono text-[9px] font-bold uppercase tracking-[0.18em]" style={{ color: QSR.inkMuted }}>
              RSA circuit
            </span>
            <Segmented
              accent={QSR.model}
              value={model}
              onChange={(value) => setModel(value)}
              options={[
                { value: 'gidney-ekera-2021' as EstimatorModel, label: '2021', title: 'Gidney & Ekerå: 20M qubits, 8 hours' },
                { value: 'gidney-2025' as EstimatorModel, label: '2025', title: 'Gidney: under 1M qubits, under a week' },
              ]}
            />
            <p className="mt-1.5 text-[10.5px] leading-snug" style={{ color: QSR.inkFaint }}>
              Four years of circuit optimisation cut the machine size by a factor of twenty at the cost of runtime. Nothing about
              the hardware changed — this is the part of the timeline that does not need a lab.
            </p>
          </div>

          <Slider
            label="RSA modulus"
            accent={QSR.model}
            min={1024}
            max={4096}
            step={1024}
            value={rsaBits}
            onChange={setRsaBits}
            format={(value) => `${value}-bit`}
          />

          <Slider
            label="Physical error rate"
            accent={QSR.model}
            min={0}
            max={ERROR_RATES.length - 1}
            value={errorRate}
            onChange={setErrorRate}
            format={(index) => ERROR_RATES[index].toExponential(0)}
            hint="The surface-code threshold is 1e-2. At or above it, adding qubits makes the machine worse rather than better."
          />

          <Slider
            label="Code cycle time"
            accent={QSR.model}
            min={100}
            max={5000}
            step={100}
            value={cycleNs}
            onChange={setCycleNs}
            format={(value) => `${value} ns`}
          />

          <div className="rounded-lg border p-3" style={{ borderColor: QSR.hairline, background: 'rgba(4,7,16,0.5)' }}>
            <div className="mb-1.5 font-mono text-[9px] font-bold uppercase tracking-[0.18em]" style={{ color: QSR.inkMuted }}>
              Largest reported device
            </div>
            <DataRow label={largestDevice.name} value={`${largestDevice.qubits.toLocaleString()} qubits`} accent={QSR.live} />
            <p className="mt-1.5 text-[10.5px] leading-snug" style={{ color: QSR.inkFaint }}>
              A physical qubit count, not error-corrected logical qubits — which is why the gap below is the honest measure.
            </p>
            {gap !== null && (
              <div className="mt-2">
                <div className="font-mono text-[19px] font-bold" style={{ color: QSR.model }}>
                  {formatCount(gap)}×
                </div>
                <div className="font-mono text-[9px] uppercase tracking-[0.14em]" style={{ color: QSR.inkFaint }}>
                  more qubits needed
                </div>
              </div>
            )}
          </div>
        </div>

        <div className="min-w-0 space-y-4">
          <div className="grid gap-3 md:grid-cols-2">
            <EstimateColumn estimate={rsa} label={`RSA-${rsaBits}`} />
            <EstimateColumn estimate={ecc} label="ECC P-256 (ECDH / ECDSA)" />
          </div>

          <Callout tone="warn" title="The result people find backwards">
            Elliptic curves are CHEAPER to break than RSA at equivalent classical strength. P-256 needs about 2,330 logical
            qubits against roughly 6,190 for RSA-2048 — so the modern, smaller, faster key is the one that falls first.{' '}
            <Cite source="roetteler" inline />
          </Callout>

          <div className="rounded-lg border p-3.5" style={{ borderColor: QSR.hairline, background: 'rgba(4,7,16,0.5)' }}>
            <div className="mb-2 flex items-center gap-1.5">
              <Cpu className="h-3.5 w-3.5" style={{ color: QSR.live }} />
              <span className="font-mono text-[9px] font-bold uppercase tracking-[0.18em]" style={{ color: QSR.inkMuted }}>
                Where the hardware actually is
              </span>
            </div>
            <div className="space-y-0">
              {REPORTED_DEVICES.map((device) => (
                <DataRow key={device.name} label={`${device.name} (${device.year})`} value={`${device.qubits.toLocaleString()} qubits`} />
              ))}
            </div>
            <p className="mt-2 text-[11px] leading-snug" style={{ color: QSR.inkFaint }}>
              {REPORTED_DEVICES.find((d) => d.name.includes('Willow'))?.note} Qubit count is the headline; error rate is the
              constraint.
            </p>
          </div>
        </div>
      </div>
    </Panel>
  );
}

/* ═══════════════════════════════════════════════════════════ Mosca calculator */

export function MoscaLab({ defaultShelfLife }: { defaultShelfLife: number }) {
  const [shelfLife, setShelfLife] = React.useState(defaultShelfLife);
  const [migration, setMigration] = React.useState(5);
  const [crqc, setCrqc] = React.useState(15);

  React.useEffect(() => setShelfLife(defaultShelfLife), [defaultShelfLife]);

  const result = React.useMemo(() => evaluateMosca({ shelfLifeYears: shelfLife, migrationYears: migration, crqcYears: crqc }), [shelfLife, migration, crqc]);
  const estimates = React.useMemo(() => crqcEstimates(), []);
  const accent = result.verdict === 'exposed' ? QSR.broken : result.verdict === 'marginal' ? QSR.model : QSR.safe;

  const span = Math.max(result.totalYears, result.crqcYears) + 2;

  return (
    <Panel
      accent={accent}
      eyebrow="Laboratory 03 · Mosca's inequality"
      title="Are you already too late?"
      subtitle={
        <>
          X + Y &gt; Z. If the time your data must stay secret plus the time your migration takes exceeds the time until a
          quantum computer exists, then some of the data you send before migration finishes will still need to be secret when it becomes readable. <Cite source="mosca" inline />
        </>
      }
      right={<ProvenanceBadge kind="model" />}
    >
      <div className="grid gap-5 lg:grid-cols-[320px_minmax(0,1fr)]">
        <div className="space-y-4">
          <Slider label="X · data shelf life" accent={QSR.broken} min={1} max={100} value={shelfLife} onChange={setShelfLife} format={(v) => `${v} years`} />
          <div className="flex flex-wrap gap-1">
            {SHELF_LIFE_PRESETS.filter((preset) => preset.years >= 1).map((preset) => (
              <button
                key={preset.id}
                type="button"
                onClick={() => setShelfLife(preset.years)}
                title={preset.basis}
                className="rounded border px-1.5 py-[3px] font-mono text-[9px] transition-colors"
                style={{
                  borderColor: shelfLife === preset.years ? tint(QSR.broken, 0.4) : QSR.hairline,
                  color: shelfLife === preset.years ? QSR.broken : QSR.inkMuted,
                  background: shelfLife === preset.years ? tint(QSR.broken, 0.1) : 'transparent',
                }}
              >
                {preset.label}
              </button>
            ))}
          </div>

          <Slider label="Y · migration duration" accent={QSR.model} min={1} max={20} value={migration} onChange={setMigration} format={(v) => `${v} years`} hint="Federal PQC migration programmes are budgeted across a decade. An enterprise estate with embedded and vendor systems rarely completes in under five." />

          <Slider label="Z · years until a CRQC" accent={QSR.quantum} min={3} max={40} value={crqc} onChange={setCrqc} format={(v) => `${v} years`} />
          <div className="space-y-1">
            {estimates.map((estimate) => (
              <button
                key={estimate.id}
                type="button"
                onClick={() => setCrqc(estimate.years)}
                title={estimate.source}
                className="block w-full rounded border px-2 py-1.5 text-left transition-colors"
                style={{
                  borderColor: crqc === estimate.years ? tint(QSR.quantum, 0.4) : QSR.hairline,
                  background: crqc === estimate.years ? tint(QSR.quantum, 0.1) : 'transparent',
                }}
              >
                <span className="font-mono text-[10px] font-bold" style={{ color: crqc === estimate.years ? QSR.quantum : QSR.inkSoft }}>
                  {estimate.label}
                </span>
                <span className="mt-0.5 block text-[10px] leading-snug" style={{ color: QSR.inkFaint }}>
                  {estimate.source}
                </span>
              </button>
            ))}
          </div>
        </div>

        <div className="min-w-0 space-y-4">
          <div className="rounded-xl border p-4" style={{ borderColor: tint(accent, 0.35), background: tint(accent, 0.07) }}>
            <div className="flex flex-wrap items-baseline justify-between gap-2">
              <span className="font-mono text-[10px] font-bold uppercase tracking-[0.2em]" style={{ color: accent }}>
                {result.verdict}
              </span>
              <span className="font-mono text-[11px]" style={{ color: QSR.inkFaint }}>
                X {result.shelfLifeYears} + Y {result.migrationYears} = {result.totalYears} vs Z {result.crqcYears}
              </span>
            </div>
            <div className="mt-1 text-[26px] font-black leading-tight" style={{ color: accent }}>
              {result.headline}
            </div>
            <p className="mt-2 text-[12.5px] leading-relaxed" style={{ color: QSR.inkSoft }}>
              {result.guidance}
            </p>
          </div>

          {/* Timeline */}
          <div className="rounded-lg border p-4" style={{ borderColor: QSR.hairline, background: 'rgba(4,7,16,0.55)' }}>
            <div className="mb-3 font-mono text-[9px] font-bold uppercase tracking-[0.18em]" style={{ color: QSR.inkMuted }}>
              Data captured today, on a calendar
            </div>
            <div className="space-y-3">
              {[
                { label: `Migration completes (${result.protectedFromYear})`, from: 0, to: result.migrationYears, colour: QSR.model, note: 'Traffic after this point is protected. Traffic before it is not.' },
                { label: `Data still confidential until ${result.baseYear + result.shelfLifeYears}`, from: 0, to: result.shelfLifeYears, colour: QSR.live, note: 'The window during which disclosure still causes harm.' },
                { label: `CRQC expected ${result.breachYear}`, from: result.crqcYears, to: result.crqcYears + 0.4, colour: QSR.broken, note: 'Everything recorded before migration completed becomes readable here.' },
              ].map((band) => (
                <div key={band.label}>
                  <div className="mb-1 flex items-baseline justify-between gap-2">
                    <span className="text-[11px] font-semibold" style={{ color: band.colour }}>
                      {band.label}
                    </span>
                  </div>
                  <div className="relative h-2.5 w-full overflow-hidden rounded-full" style={{ background: 'rgba(148,163,184,0.09)' }}>
                    <motion.div
                      className="absolute inset-y-0 rounded-full"
                      initial={false}
                      animate={{ left: `${(band.from / span) * 100}%`, width: `${((band.to - band.from) / span) * 100}%` }}
                      transition={{ type: 'spring', stiffness: 110, damping: 22 }}
                      style={{ background: band.colour, boxShadow: `0 0 10px ${tint(band.colour, 0.5)}` }}
                    />
                  </div>
                  <div className="mt-1 text-[10.5px] leading-snug" style={{ color: QSR.inkFaint }}>
                    {band.note}
                  </div>
                </div>
              ))}
            </div>
            <div className="mt-3 flex justify-between font-mono text-[9px]" style={{ color: QSR.inkFaint }}>
              <span>{result.baseYear}</span>
              <span>{result.baseYear + Math.round(span / 2)}</span>
              <span>{result.baseYear + Math.round(span)}</span>
            </div>
          </div>

          <div className="grid gap-2.5 sm:grid-cols-3">
            <StatTile label="Latest safe start" value={result.latestStartYear} provenance="model" accent={result.latestStartYear < result.baseYear ? QSR.broken : QSR.safe} note={result.latestStartYear < result.baseYear ? 'already passed' : 'still ahead'} />
            <StatTile label="Exposure" value={result.exposureYears > 0 ? `+${result.exposureYears}` : result.exposureYears} unit="years" provenance="model" accent={accent} />
            <StatTile label="Years already lost" value={result.alreadyLostYears} provenance="model" accent={result.alreadyLostYears > 0 ? QSR.broken : QSR.safe} note="of captured traffic" />
          </div>

          <div className="flex flex-wrap gap-1.5">
            <Chip label="X" value="how long the data must stay secret" />
            <Chip label="Y" value="how long migration takes" />
            <Chip label="Z" value="how long until a CRQC" />
            <Chip label="Rule" value="X + Y > Z means already exposed" accent={QSR.broken} />
          </div>
        </div>
      </div>
    </Panel>
  );
}
