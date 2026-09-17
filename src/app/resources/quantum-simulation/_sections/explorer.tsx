/**
 * Quantum Simulation Range — the explainers.
 *
 *   VulnerabilityLedger  every classical primitive, what happens to it, and why
 *   GroverPanel          the correction: Grover is a reduction, not a break
 *   PqcSuite             FIPS 203/204/205 parameter sets, benchmarked live
 *   StandardsTimeline    the published transition deadlines, in order
 *
 * The ledger and the Grover panel exist because of one specific failure in the
 * page this replaces: it listed "AES/RSA" as broken and described Grover as
 * "reducing symmetric key strength" alongside Shor as if the two were the same
 * kind of event. They are not, and getting that wrong sends a reader off to
 * replace primitives that do not need replacing while leaving the ones that do.
 */

import React from 'react';
import { AnimatePresence, motion } from 'framer-motion';
import { ChevronRight, Gauge, ShieldCheck, Zap } from 'lucide-react';
import {
  CLASSICAL_PRIMITIVES,
  GROVER_REALITY,
  ML_DSA_SETS,
  ML_KEM_SETS,
  NIST_SECURITY_CATEGORY,
  PENDING_STANDARDS,
  SLH_DSA_SETS,
  TRANSITION_MILESTONES,
  benchmarkPqc,
  complexityCurve,
  formatBytes,
  groverEvolution,
  groverFeasibility,
  milestoneClock,
  type BenchmarkRow,
  type ClassicalPrimitive,
  type PqcParameterSet,
} from '@/lib/quantum-sim';
import { useEmit } from '../_state';
import { QSR, VERDICT_COLOR, VERDICT_LABEL, tint } from '../_theme';
import { ActionButton, Callout, Chip, Cite, DataRow, Panel, ProvenanceBadge, Segmented, Slider, StatTile } from '../_ui';

/* ═══════════════════════════════════════════════════════ vulnerability ledger */

function LedgerRow({ item, open, onToggle }: { item: ClassicalPrimitive; open: boolean; onToggle: () => void }) {
  const accent = VERDICT_COLOR[item.verdict];
  return (
    <div className="border-b last:border-b-0" style={{ borderColor: 'rgba(56,189,248,0.07)' }}>
      <button type="button" onClick={onToggle} className="flex w-full items-center gap-3 px-3.5 py-2.5 text-left transition-colors hover:bg-cyan-400/[0.04]">
        <ChevronRight className="h-3.5 w-3.5 shrink-0 transition-transform" style={{ color: QSR.inkFaint, transform: open ? 'rotate(90deg)' : undefined }} />
        <span className="w-[168px] shrink-0 font-mono text-[12px] font-bold" style={{ color: QSR.ink }}>
          {item.name}
        </span>
        <span className="hidden w-[112px] shrink-0 font-mono text-[10px] uppercase tracking-[0.1em] sm:block" style={{ color: QSR.inkMuted }}>
          {item.role.replace('-', ' ')}
        </span>
        <span className="hidden w-[92px] shrink-0 font-mono text-[11px] md:block" style={{ color: QSR.inkSoft }}>
          {item.classicalBits} bit
        </span>
        <span className="hidden w-[86px] shrink-0 font-mono text-[11px] md:block" style={{ color: item.verdict === 'broken' ? QSR.broken : QSR.inkSoft }}>
          {item.attack === 'shor' ? '0 bit' : `${item.quantumBits} bit`}
        </span>
        <span className="ml-auto shrink-0 rounded-[3px] border px-1.5 py-[3px] font-mono text-[9px] font-bold uppercase tracking-[0.1em]" style={{ color: accent, borderColor: tint(accent, 0.3), background: tint(accent, 0.08) }}>
          {VERDICT_LABEL[item.verdict]}
        </span>
      </button>

      <AnimatePresence initial={false}>
        {open && (
          <motion.div initial={{ height: 0, opacity: 0 }} animate={{ height: 'auto', opacity: 1 }} exit={{ height: 0, opacity: 0 }} transition={{ duration: 0.22 }} className="overflow-hidden">
            <div className="space-y-3 px-3.5 pb-4 pl-10">
              <div>
                <div className="font-mono text-[9px] font-bold uppercase tracking-[0.16em]" style={{ color: QSR.inkFaint }}>
                  What the attacker recovers
                </div>
                <p className="mt-0.5 text-[12px] leading-relaxed" style={{ color: QSR.inkSoft }}>
                  {item.target}
                </p>
              </div>
              <div>
                <div className="font-mono text-[9px] font-bold uppercase tracking-[0.16em]" style={{ color: QSR.inkFaint }}>
                  Mechanism
                </div>
                <p className="mt-0.5 text-[12px] leading-relaxed" style={{ color: QSR.inkSoft }}>
                  {item.mechanism}
                </p>
              </div>
              <div className="flex flex-wrap gap-1.5">
                <Chip label="Replace with" value={item.replacement} accent={item.verdict === 'broken' ? QSR.quantum : QSR.safe} />
                {item.transition.deprecatedAfter && <Chip label="Deprecated after" value={item.transition.deprecatedAfter} accent={QSR.model} />}
                {item.transition.disallowedAfter && <Chip label="Disallowed after" value={item.transition.disallowedAfter} accent={QSR.broken} />}
                <Cite source={item.citation} />
              </div>
            </div>
          </motion.div>
        )}
      </AnimatePresence>
    </div>
  );
}

/** GNFS vs Shor, plotted so the shape of the difference is visible at a glance. */
function ComplexityChart({ kind }: { kind: 'rsa' | 'ecc' }) {
  const points = React.useMemo(() => complexityCurve(kind, kind === 'rsa' ? 512 : 160, kind === 'rsa' ? 8192 : 768, 40), [kind]);
  const maxY = Math.max(...points.map((p) => Math.max(p.classical, p.quantum)));
  const width = 100;
  const height = 46;

  const toPath = (key: 'classical' | 'quantum') =>
    points
      .map((point, index) => {
        const x = (index / (points.length - 1)) * width;
        const y = height - (point[key] / maxY) * (height - 4);
        return `${index === 0 ? 'M' : 'L'} ${x.toFixed(2)} ${y.toFixed(2)}`;
      })
      .join(' ');

  return (
    <div>
      <svg viewBox={`0 0 ${width} ${height}`} preserveAspectRatio="none" className="h-[120px] w-full">
        <path d={toPath('classical')} fill="none" stroke={QSR.safe} strokeWidth={0.8} vectorEffect="non-scaling-stroke" />
        <path d={toPath('quantum')} fill="none" stroke={QSR.broken} strokeWidth={0.8} vectorEffect="non-scaling-stroke" />
      </svg>
      <div className="mt-1 flex items-center justify-between font-mono text-[9px]" style={{ color: QSR.inkFaint }}>
        <span>{points[0].bits} bit</span>
        <span className="flex gap-3">
          <span style={{ color: QSR.safe }}>— classical cost</span>
          <span style={{ color: QSR.broken }}>— quantum cost</span>
        </span>
        <span>{points[points.length - 1].bits} bit</span>
      </div>
    </div>
  );
}

export function VulnerabilityLedger() {
  const [open, setOpen] = React.useState<string | null>('rsa-2048');
  const [curve, setCurve] = React.useState<'rsa' | 'ecc'>('rsa');

  const broken = CLASSICAL_PRIMITIVES.filter((p) => p.verdict === 'broken').length;
  const safe = CLASSICAL_PRIMITIVES.filter((p) => p.verdict !== 'broken').length;

  return (
    <Panel
      accent={QSR.broken}
      eyebrow="The vulnerability logic"
      title="What actually breaks, and what does not"
      subtitle="There are two quantum algorithms that matter and they do very different things. Confusing them is the most common and most expensive mistake in quantum-risk planning."
      right={<ProvenanceBadge kind="published" />}
    >
      <div className="grid gap-4 lg:grid-cols-[minmax(0,1fr)_300px]">
        <div className="min-w-0">
          <div className="rounded-lg border" style={{ borderColor: QSR.hairline, background: 'rgba(4,7,16,0.5)' }}>
            <div className="flex items-center gap-3 border-b px-3.5 py-2 font-mono text-[9px] font-bold uppercase tracking-[0.14em]" style={{ borderColor: QSR.hairline, color: QSR.inkFaint }}>
              <span className="w-3.5" />
              <span className="w-[168px]">Primitive</span>
              <span className="hidden w-[112px] sm:block">Role</span>
              <span className="hidden w-[92px] md:block">Classical</span>
              <span className="hidden w-[86px] md:block">Quantum</span>
              <span className="ml-auto">Verdict</span>
            </div>
            {CLASSICAL_PRIMITIVES.map((item) => (
              <LedgerRow key={item.id} item={item} open={open === item.id} onToggle={() => setOpen(open === item.id ? null : item.id)} />
            ))}
          </div>
        </div>

        <div className="space-y-3">
          <div className="grid grid-cols-2 gap-2.5">
            <StatTile label="Fully broken" value={broken} provenance="published" accent={QSR.broken} note="public-key only" />
            <StatTile label="Survives" value={safe} provenance="published" accent={QSR.safe} note="symmetric & hashes" />
          </div>

          <div className="rounded-lg border p-3.5" style={{ borderColor: QSR.hairline, background: 'rgba(4,7,16,0.5)' }}>
            <div className="mb-2 flex items-center justify-between">
              <span className="font-mono text-[9px] font-bold uppercase tracking-[0.16em]" style={{ color: QSR.inkMuted }}>
                Cost vs key size
              </span>
              <Segmented<'rsa' | 'ecc'>
                size="sm"
                accent={QSR.broken}
                value={curve}
                onChange={setCurve}
                options={[
                  { value: 'rsa', label: 'RSA' },
                  { value: 'ecc', label: 'ECC' },
                ]}
              />
            </div>
            <ComplexityChart kind={curve} />
            <p className="mt-2 text-[11px] leading-snug" style={{ color: QSR.inkFaint }}>
              {curve === 'rsa'
                ? 'The classical curve is the General Number Field Sieve, which is sub-exponential. The quantum curve is polynomial. Growing the modulus climbs a steep hill for the defender and a gentle one for the attacker.'
                : 'For elliptic curves the classical attack is Pollard rho at exactly half the curve size, and the quantum cost is again polynomial. This is why P-521 is not a hiding place.'}
            </p>
          </div>

          <Callout tone="good" title="The part that is good news">
            <span className="flex items-start gap-2">
              <ShieldCheck className="mt-0.5 h-3.5 w-3.5 shrink-0" style={{ color: QSR.safe }} />
              <span>{GROVER_REALITY.practicalGuidance} Your AES, your SHA-2 and your HMAC are not the problem.</span>
            </span>
          </Callout>
        </div>
      </div>
    </Panel>
  );
}

/* ═══════════════════════════════════════════════════════════════ Grover panel */

export function GroverPanel() {
  const [keyBits, setKeyBits] = React.useState(128);
  const [machines, setMachines] = React.useState(0); // log10

  const evolution = React.useMemo(() => groverEvolution(Math.min(keyBits, 24)), [keyBits]);
  const feasibility = React.useMemo(() => groverFeasibility(keyBits, 1e9, 10 ** machines), [keyBits, machines]);

  const path = React.useMemo(() => {
    if (evolution.curve.length === 0) return '';
    const maxIteration = evolution.curve[evolution.curve.length - 1].iteration || 1;
    return evolution.curve
      .map((point, index) => {
        const x = (point.iteration / maxIteration) * 100;
        const y = 44 - point.probability * 40;
        return `${index === 0 ? 'M' : 'L'} ${x.toFixed(2)} ${y.toFixed(2)}`;
      })
      .join(' ');
  }, [evolution]);

  return (
    <Panel
      accent={QSR.model}
      eyebrow="The other algorithm"
      title="Grover: a reduction, not a break"
      subtitle={
        <>
          Grover's search turns an exhaustive key search of size N into √N. That is a real speed-up and it is not an attack —
          the amplitude curve below is the exact quantum state, sin((2j+1)·θ), not an approximation. <Cite source="grover1996" inline />
        </>
      }
      right={<ProvenanceBadge kind="model" />}
    >
      <div className="grid gap-4 lg:grid-cols-[300px_minmax(0,1fr)]">
        <div className="space-y-4">
          <Slider label="Symmetric key length" accent={QSR.model} min={64} max={256} step={64} value={keyBits} onChange={setKeyBits} format={(value) => `${value} bit`} />
          <Slider
            label="Quantum computers in parallel"
            accent={QSR.model}
            min={0}
            max={9}
            value={machines}
            onChange={setMachines}
            format={(value) => (value === 0 ? '1' : `10^${value}`)}
            hint="Watch what parallelism buys. A classical key search splits linearly across machines; Grover splits as the square root."
          />

          <div className="grid grid-cols-2 gap-2.5">
            <StatTile label="Operations" value={`2^${feasibility.operationsBits.toFixed(0)}`} provenance="model" accent={QSR.model} note="sequential" />
            <StatTile label="Speed-up from parallelism" value={`${feasibility.parallelSpeedup.toFixed(0)}×`} provenance="model" accent={QSR.live} note={`on 10^${machines} machines`} />
          </div>

          <div className="rounded-lg border p-3" style={{ borderColor: QSR.hairline, background: 'rgba(4,7,16,0.5)' }}>
            <div className="mb-1.5 font-mono text-[9px] font-bold uppercase tracking-[0.16em]" style={{ color: QSR.inkMuted }}>
              NIST MAXDEPTH bounds
            </div>
            <DataRow label="Conservative (2^40)" value={feasibility.exceedsMaxDepth.conservative ? 'exceeded' : 'within'} accent={feasibility.exceedsMaxDepth.conservative ? QSR.broken : QSR.safe} />
            <DataRow label="Plausible (2^64)" value={feasibility.exceedsMaxDepth.plausible ? 'exceeded' : 'within'} accent={feasibility.exceedsMaxDepth.plausible ? QSR.broken : QSR.safe} />
            <DataRow label="Generous (2^96)" value={feasibility.exceedsMaxDepth.generous ? 'exceeded' : 'within'} accent={feasibility.exceedsMaxDepth.generous ? QSR.broken : QSR.safe} />
          </div>
        </div>

        <div className="min-w-0 space-y-4">
          <div className="rounded-lg border p-3.5" style={{ borderColor: QSR.hairline, background: 'rgba(4,7,16,0.55)' }}>
            <div className="mb-1.5 flex items-center justify-between">
              <span className="font-mono text-[9px] font-bold uppercase tracking-[0.16em]" style={{ color: QSR.inkMuted }}>
                Amplitude amplification — success probability per iteration
              </span>
              <span className="font-mono text-[9.5px]" style={{ color: QSR.inkFaint }}>
                drawn for a {Math.min(keyBits, 24)}-bit space so it is plottable
              </span>
            </div>
            <svg viewBox="0 0 100 46" preserveAspectRatio="none" className="h-[130px] w-full">
              <line x1={0} y1={4} x2={100} y2={4} stroke={tint(QSR.safe, 0.3)} strokeWidth={0.4} strokeDasharray="2 2" vectorEffect="non-scaling-stroke" />
              <path d={path} fill="none" stroke={QSR.model} strokeWidth={1} vectorEffect="non-scaling-stroke" />
            </svg>
            <p className="mt-1.5 text-[11px] leading-snug" style={{ color: QSR.inkFaint }}>
              The probability rises to near-certainty and then falls again — over-rotating past the optimum makes Grover WORSE.
              You must know when to stop, which means you must know how many solutions exist.
            </p>
          </div>

          <div className="rounded-xl border p-4" style={{ borderColor: tint(feasibility.verdict === 'infeasible' ? QSR.safe : QSR.model, 0.3), background: tint(feasibility.verdict === 'infeasible' ? QSR.safe : QSR.model, 0.06) }}>
            <div className="flex items-center gap-2">
              <Zap className="h-4 w-4" style={{ color: feasibility.verdict === 'infeasible' ? QSR.safe : QSR.model }} />
              <span className="font-mono text-[10px] font-bold uppercase tracking-[0.2em]" style={{ color: feasibility.verdict === 'infeasible' ? QSR.safe : QSR.model }}>
                {feasibility.verdict.replace('-', ' ')}
              </span>
            </div>
            <p className="mt-2 text-[12.5px] leading-relaxed" style={{ color: QSR.inkSoft }}>
              {feasibility.explanation}
            </p>
          </div>

          <Callout tone="info" title={GROVER_REALITY.headline}>
            {GROVER_REALITY.detail}
          </Callout>
        </div>
      </div>
    </Panel>
  );
}

/* ═══════════════════════════════════════════════════════════════ PQC suite */

function ParameterTable({ title, sets, accent }: { title: string; sets: PqcParameterSet[]; accent: string }) {
  const role = sets[0]?.role;
  return (
    <div className="rounded-lg border" style={{ borderColor: QSR.hairline, background: 'rgba(4,7,16,0.5)' }}>
      <div className="flex items-center justify-between border-b px-3.5 py-2" style={{ borderColor: QSR.hairline }}>
        <span className="font-mono text-[10px] font-bold uppercase tracking-[0.16em]" style={{ color: accent }}>
          {title}
        </span>
        <Cite source={sets[0].citation} />
      </div>
      <div className="overflow-x-auto">
        <table className="w-full min-w-[420px] font-mono text-[11px]">
          <thead>
            <tr style={{ color: QSR.inkFaint }}>
              <th className="px-3.5 py-1.5 text-left font-normal">Set</th>
              <th className="px-2 py-1.5 text-right font-normal">Cat</th>
              <th className="px-2 py-1.5 text-right font-normal">Public</th>
              <th className="px-2 py-1.5 text-right font-normal">Secret</th>
              <th className="px-3.5 py-1.5 text-right font-normal">{role === 'kem' ? 'Ciphertext' : 'Signature'}</th>
            </tr>
          </thead>
          <tbody>
            {sets.map((set) => (
              <tr key={set.id} className="border-t" style={{ borderColor: 'rgba(56,189,248,0.05)' }}>
                <td className="px-3.5 py-1.5 font-bold" style={{ color: QSR.ink }} title={set.note}>
                  {set.id}
                </td>
                <td className="px-2 py-1.5 text-right" style={{ color: accent }} title={NIST_SECURITY_CATEGORY[set.category]?.meaning}>
                  {set.category}
                </td>
                <td className="px-2 py-1.5 text-right" style={{ color: QSR.inkSoft }}>
                  {formatBytes(set.sizes.publicKey)}
                </td>
                <td className="px-2 py-1.5 text-right" style={{ color: QSR.inkSoft }}>
                  {formatBytes(set.sizes.secretKey)}
                </td>
                <td className="px-3.5 py-1.5 text-right" style={{ color: QSR.inkSoft }}>
                  {formatBytes(role === 'kem' ? set.sizes.ciphertext : set.sizes.signature)}
                </td>
              </tr>
            ))}
          </tbody>
        </table>
      </div>
    </div>
  );
}

export function PqcSuite({ active }: { active: boolean }) {
  const emit = useEmit();
  const [rows, setRows] = React.useState<BenchmarkRow[] | null>(null);
  const [busy, setBusy] = React.useState(false);

  const run = React.useCallback(() => {
    setBusy(true);
    // Timer, not rAF — see the note in the Shor laboratory: rAF does not fire
    // in a background tab, and a stalled benchmark is worse than a slow one.
    setTimeout(() => {
      const measured = benchmarkPqc(360);
      setRows(measured);
      setBusy(false);
      const kem = measured.find((row) => row.algorithm === 'ML-KEM-768');
      const dsa = measured.find((row) => row.algorithm === 'ML-DSA-65');
      emit(
        'measure',
        'bench',
        `${measured.length} algorithms benchmarked on this machine${kem ? ` · ML-KEM-768 encap ${kem.primaryMs.toFixed(3)}ms over ${kem.samples} samples` : ''}${dsa ? ` · ML-DSA-65 sign ${dsa.primaryMs.toFixed(3)}ms` : ''}`,
      );
    });
  }, [emit]);

  React.useEffect(() => {
    if (active && !rows && !busy) run();
    // eslint-disable-next-line react-hooks/exhaustive-deps
  }, [active]);

  const slowest = rows ? Math.max(...rows.map((row) => Math.max(row.keygenMs, row.primaryMs, row.secondaryMs))) : 1;

  return (
    <Panel
      accent={QSR.quantum}
      eyebrow="The replacement suite"
      title="FIPS 203, 204 and 205 — sizes and speed"
      subtitle="Published parameter sets on the left, your own machine on the right. The most common objection to migrating is that post-quantum cryptography is too slow; this is what it actually costs here. The SLH-DSA table lists the small (s) sets — the benchmark below also runs the fast (f) variant, which trades a much larger signature for quicker signing — and each SLH-DSA row covers both the SHA2 and SHAKE instantiations FIPS 205 defines, since their sizes are identical."
      right={<ProvenanceBadge kind="measured" />}
    >
      <div className="space-y-4">
        <div className="grid gap-3 lg:grid-cols-3">
          <ParameterTable title="ML-KEM · key establishment" sets={ML_KEM_SETS} accent={QSR.quantum} />
          <ParameterTable title="ML-DSA · signatures" sets={ML_DSA_SETS} accent={QSR.live} />
          <ParameterTable title="SLH-DSA · hash-based, small (s) sets" sets={SLH_DSA_SETS.filter((s) => s.id.endsWith('s'))} accent={QSR.safe} />
        </div>

        <div className="rounded-lg border" style={{ borderColor: tint(QSR.live, 0.2), background: 'rgba(4,7,16,0.55)' }}>
          <div className="flex flex-wrap items-center justify-between gap-3 border-b px-3.5 py-2.5" style={{ borderColor: QSR.hairline }}>
            <span className="flex items-center gap-1.5">
              <Gauge className="h-3.5 w-3.5" style={{ color: QSR.live }} />
              <span className="font-mono text-[10px] font-bold uppercase tracking-[0.16em]" style={{ color: QSR.live }}>
                Benchmarked in this browser
              </span>
            </span>
            <ActionButton variant="ghost" onClick={run} busy={busy}>
              Re-run benchmark
            </ActionButton>
          </div>

          {rows ? (
            <div className="overflow-x-auto">
              <table className="w-full min-w-[620px] font-mono text-[11px]">
                <thead>
                  <tr style={{ color: QSR.inkFaint }}>
                    <th className="px-3.5 py-2 text-left font-normal">Algorithm</th>
                    <th className="px-2 py-2 text-right font-normal">keygen</th>
                    <th className="px-2 py-2 text-right font-normal">encap / sign</th>
                    <th className="px-2 py-2 text-right font-normal">decap / verify</th>
                    <th className="px-2 py-2 text-left font-normal">relative</th>
                    <th className="px-3.5 py-2 text-right font-normal">wire</th>
                  </tr>
                </thead>
                <tbody>
                  {rows.map((row) => {
                    const accent = row.role === 'kem' ? QSR.quantum : row.algorithm.startsWith('SLH') ? QSR.safe : QSR.live;
                    return (
                      <tr key={row.algorithm} className="border-t" style={{ borderColor: 'rgba(56,189,248,0.05)' }}>
                        <td className="px-3.5 py-1.5 font-bold" style={{ color: accent }}>
                          {row.algorithm}
                        </td>
                        <td className="px-2 py-1.5 text-right" style={{ color: QSR.inkSoft }}>
                          {row.keygenMs.toFixed(2)} ms
                        </td>
                        <td className="px-2 py-1.5 text-right" style={{ color: QSR.inkSoft }}>
                          {row.primaryMs.toFixed(2)} ms
                        </td>
                        <td className="px-2 py-1.5 text-right" style={{ color: QSR.inkSoft }}>
                          {row.secondaryMs.toFixed(2)} ms
                        </td>
                        <td className="px-2 py-1.5">
                          <span className="block h-1.5 rounded-full" style={{ width: `${Math.max(2, (row.primaryMs / slowest) * 100)}%`, background: accent, minWidth: 4 }} />
                        </td>
                        <td className="px-3.5 py-1.5 text-right" style={{ color: QSR.inkMuted }}>
                          {(row.wireBytes / 1024).toFixed(2)} KiB
                        </td>
                      </tr>
                    );
                  })}
                </tbody>
              </table>
            </div>
          ) : (
            <div className="px-3.5 py-6 text-center text-[12px]" style={{ color: QSR.inkFaint }}>
              {busy ? 'Running…' : 'Scroll here to benchmark.'}
            </div>
          )}
        </div>

        <div className="grid gap-3 md:grid-cols-2">
          <Callout tone="good" title="What the numbers say">
            ML-KEM and ML-DSA run in single-digit milliseconds. The real migration cost is not CPU — it is the wire: a hybrid
            X25519MLKEM768 key share is 1,216 bytes against 32 for X25519, which pushes the ClientHello past a single TCP
            segment and is where deployment problems actually show up.
          </Callout>
          <Callout tone="warn" title="Still to come">
            <div className="space-y-2">
              {PENDING_STANDARDS.map((standard) => (
                <div key={standard.id}>
                  <span className="font-mono text-[11px] font-bold" style={{ color: QSR.model }}>
                    {standard.id}
                  </span>
                  <span className="ml-1.5 text-[11px]" style={{ color: QSR.inkSoft }}>
                    {standard.summary}
                  </span>
                </div>
              ))}
            </div>
          </Callout>
        </div>
      </div>
    </Panel>
  );
}

/* ═══════════════════════════════════════════════════════════ standards timeline */

export function StandardsTimeline({ now }: { now: number }) {
  const ordered = React.useMemo(() => [...TRANSITION_MILESTONES].sort((a, b) => Date.parse(a.date) - Date.parse(b.date)), []);

  return (
    <Panel
      accent={QSR.live}
      eyebrow="The published clock"
      title="Transition deadlines, in order"
      subtitle="Not predictions. These are dates in released government publications, and they are the dates a compliance programme is measured against."
      right={<ProvenanceBadge kind="published" />}
    >
      <div className="relative">
        <div className="absolute bottom-2 left-[7px] top-2 w-px" style={{ background: 'linear-gradient(180deg, rgba(34,211,238,0.35), rgba(244,63,94,0.35))' }} />
        <div className="space-y-3">
          {ordered.map((milestone) => {
            const clock = milestoneClock(milestone, now);
            const accent = milestone.severity === 'hard-stop' ? QSR.broken : milestone.severity === 'deadline' ? QSR.model : QSR.live;
            return (
              <div key={milestone.id} className="relative pl-7">
                <span className="absolute left-0 top-2 h-[15px] w-[15px] rounded-full border-2" style={{ borderColor: accent, background: clock.elapsed ? accent : QSR.panelSolid }} />
                <div className="rounded-lg border px-3.5 py-2.5" style={{ borderColor: clock.elapsed ? QSR.hairline : tint(accent, 0.24), background: clock.elapsed ? 'rgba(4,7,16,0.4)' : tint(accent, 0.05) }}>
                  <div className="flex flex-wrap items-baseline justify-between gap-2">
                    <span className="flex items-center gap-2">
                      <span className="font-mono text-[13px] font-bold" style={{ color: accent }}>
                        {milestone.date.slice(0, 4)}
                      </span>
                      <span className="rounded-[3px] border px-1.5 py-[2px] font-mono text-[8.5px] font-bold uppercase tracking-[0.12em]" style={{ color: accent, borderColor: tint(accent, 0.28) }}>
                        {milestone.authority}
                      </span>
                    </span>
                    <span className="font-mono text-[10px]" style={{ color: clock.elapsed ? QSR.inkFaint : accent }}>
                      {clock.elapsed ? 'in effect' : `${clock.days.toLocaleString()} days`}
                    </span>
                  </div>
                  <div className="mt-1 text-[12.5px] font-semibold text-slate-100">{milestone.title}</div>
                  <p className="mt-1 text-[11.5px] leading-relaxed" style={{ color: QSR.inkSoft }}>
                    {milestone.detail}
                  </p>
                  <div className="mt-1.5">
                    <Cite source={milestone.citation} />
                  </div>
                </div>
              </div>
            );
          })}
        </div>
      </div>
    </Panel>
  );
}
