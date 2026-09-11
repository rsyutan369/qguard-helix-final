/**
 * Quantum Simulation Range — the console itself.
 *
 * Scenario selector, the six-stage attack chain, the WebGL stage, and the
 * mechanism brief for whichever stage is live.
 *
 * The stage rail is deliberately marked with which stages need a quantum
 * computer to exist and which are happening now. That distinction is the single
 * most useful thing a reader can take away, and the page this replaces buried
 * it: every stage there was rendered with identical urgency, so "we recorded
 * your traffic this morning" and "a machine nobody has built decrypts it" read
 * as equally hypothetical.
 */

import React from 'react';
import { AnimatePresence, motion } from 'framer-motion';
import { ChevronDown, Pause, Play, SkipBack, SkipForward, Check, Lock } from 'lucide-react';
import { SCENARIOS, type Scenario } from '@/data/scenario';
import { ATTACK_CHAIN, namedGroup, type AttackStage, type ScenarioCryptoProfile, type ClassicalPrimitive } from '@/lib/quantum-sim';
import type { QveBudget } from '@/app/public-scan/_qve/performance-manager';
import { QSR, TENSE_COLOR, tint, VERDICT_COLOR, VERDICT_LABEL } from '../_theme';
import { Callout, Chip, Panel, ProvenanceBadge } from '../_ui';
import StageFallback from '../_three/StageFallback';
import type { StageSites } from '../_three/QuantumStage3D';

const QuantumStage3D = React.lazy(() => import('../_three/QuantumStage3D'));

/* ═════════════════════════════════════════════════════════ scenario selector */

function ScenarioSelector({ active, onSelect }: { active: Scenario; onSelect: (id: string) => void }) {
  const [open, setOpen] = React.useState(false);
  const container = React.useRef<HTMLDivElement>(null);

  React.useEffect(() => {
    if (!open) return;
    const handler = (event: MouseEvent) => {
      if (container.current && !container.current.contains(event.target as Node)) setOpen(false);
    };
    const escape = (event: KeyboardEvent) => {
      if (event.key === 'Escape') setOpen(false);
    };
    document.addEventListener('mousedown', handler);
    document.addEventListener('keydown', escape);
    return () => {
      document.removeEventListener('mousedown', handler);
      document.removeEventListener('keydown', escape);
    };
  }, [open]);

  return (
    <div ref={container} className="relative w-full sm:w-[380px]">
      <span className="mb-1.5 block font-mono text-[9px] font-bold uppercase tracking-[0.2em]" style={{ color: QSR.inkMuted }}>
        Scenario · {SCENARIOS.length} available
      </span>
      <button
        type="button"
        onClick={() => setOpen((value) => !value)}
        aria-expanded={open}
        className="flex w-full items-center gap-2.5 rounded-lg border px-3.5 py-2.5 text-left transition-colors"
        style={{ borderColor: open ? tint(QSR.live, 0.35) : QSR.hairline, background: 'rgba(4,7,16,0.7)' }}
      >
        <span className="min-w-0 flex-1">
          <span className="block truncate text-[13px] font-bold text-slate-100">{active.name}</span>
          <span className="block truncate font-mono text-[9.5px] uppercase tracking-[0.14em]" style={{ color: QSR.inkMuted }}>
            {active.category}
          </span>
        </span>
        <ChevronDown className="h-4 w-4 shrink-0 transition-transform" style={{ color: QSR.inkMuted, transform: open ? 'rotate(180deg)' : undefined }} />
      </button>

      <AnimatePresence>
        {open && (
          <motion.div
            initial={{ opacity: 0, y: -6 }}
            animate={{ opacity: 1, y: 0 }}
            exit={{ opacity: 0, y: -6 }}
            transition={{ duration: 0.15 }}
            className="qsr-scroll absolute left-0 right-0 top-full z-50 mt-1.5 max-h-[380px] overflow-y-auto rounded-lg border shadow-2xl"
            style={{ borderColor: tint(QSR.live, 0.22), background: QSR.panelSolid }}
          >
            {SCENARIOS.map((scenario) => {
              const selected = scenario.id === active.id;
              return (
                <button
                  key={scenario.id}
                  type="button"
                  onClick={() => {
                    onSelect(scenario.id);
                    setOpen(false);
                  }}
                  className="block w-full border-b px-3.5 py-2.5 text-left transition-colors last:border-b-0 hover:bg-cyan-400/[0.07]"
                  style={{ borderColor: 'rgba(56,189,248,0.07)', background: selected ? tint(QSR.live, 0.1) : undefined }}
                >
                  <span className="block text-[12px] font-semibold" style={{ color: selected ? QSR.live : QSR.ink }}>
                    {scenario.name}
                  </span>
                  <span className="block font-mono text-[9px] uppercase tracking-[0.14em]" style={{ color: QSR.inkFaint }}>
                    {scenario.category}
                  </span>
                </button>
              );
            })}
          </motion.div>
        )}
      </AnimatePresence>
    </div>
  );
}

/* ═════════════════════════════════════════════════════════════════ stage rail */

function StageRail({
  stage,
  progress,
  onSelect,
}: {
  stage: number;
  progress: number;
  onSelect: (ordinal: number) => void;
}) {
  return (
    <div className="w-full">
      <div className="mb-2 flex items-center justify-between">
        <span className="font-mono text-[9px] font-bold uppercase tracking-[0.2em]" style={{ color: QSR.inkMuted }}>
          Attack chain
        </span>
        <span className="flex items-center gap-3 font-mono text-[9px] uppercase tracking-[0.14em]">
          <span className="flex items-center gap-1" style={{ color: TENSE_COLOR.present }}>
            <span className="h-1.5 w-1.5 rounded-full" style={{ background: TENSE_COLOR.present }} /> happening now
          </span>
          <span className="flex items-center gap-1" style={{ color: TENSE_COLOR.future }}>
            <span className="h-1.5 w-1.5 rounded-full" style={{ background: TENSE_COLOR.future }} /> needs a CRQC
          </span>
          <span className="flex items-center gap-1" style={{ color: TENSE_COLOR.remedy }}>
            <span className="h-1.5 w-1.5 rounded-full" style={{ background: TENSE_COLOR.remedy }} /> remedy
          </span>
        </span>
      </div>

      <div className="grid grid-cols-3 gap-1.5 sm:grid-cols-6">
        {ATTACK_CHAIN.map((item) => {
          const active = item.ordinal === stage;
          const done = item.ordinal < stage;
          const accent = TENSE_COLOR[item.tense];
          return (
            <button
              key={item.id}
              type="button"
              onClick={() => onSelect(item.ordinal)}
              title={item.title}
              className="group relative overflow-hidden rounded-lg border px-2.5 py-2 text-left transition-colors"
              style={{
                borderColor: active ? tint(accent, 0.5) : QSR.hairline,
                background: active ? tint(accent, 0.12) : 'rgba(4,7,16,0.55)',
              }}
            >
              {active && (
                <motion.span
                  aria-hidden
                  className="absolute inset-x-0 bottom-0 h-[2px] origin-left"
                  style={{ background: accent }}
                  initial={false}
                  animate={{ scaleX: progress }}
                  transition={{ duration: 0.1, ease: 'linear' }}
                />
              )}
              <span className="flex items-center gap-1.5">
                <span
                  className="flex h-4 w-4 shrink-0 items-center justify-center rounded-full font-mono text-[9px] font-bold"
                  style={{
                    background: done ? QSR.safe : active ? accent : 'rgba(148,163,184,0.14)',
                    color: done || active ? '#04060e' : QSR.inkMuted,
                  }}
                >
                  {done ? <Check className="h-2.5 w-2.5" strokeWidth={3.5} /> : item.ordinal}
                </span>
                <span
                  className="truncate font-mono text-[10px] font-bold uppercase tracking-[0.1em]"
                  style={{ color: active ? accent : done ? QSR.inkSoft : QSR.inkMuted }}
                >
                  {item.label}
                </span>
              </span>
              {item.requiresCrqc && (
                <span className="mt-1 flex items-center gap-1 font-mono text-[8px] uppercase tracking-[0.12em]" style={{ color: QSR.inkFaint }}>
                  <Lock className="h-2 w-2" /> needs CRQC
                </span>
              )}
              {!item.requiresCrqc && item.tense === 'present' && (
                <span className="mt-1 block font-mono text-[8px] uppercase tracking-[0.12em]" style={{ color: tint(TENSE_COLOR.present, 0.85) }}>
                  live today
                </span>
              )}
              {item.tense === 'remedy' && (
                <span className="mt-1 block font-mono text-[8px] uppercase tracking-[0.12em]" style={{ color: tint(QSR.safe, 0.85) }}>
                  the fix
                </span>
              )}
            </button>
          );
        })}
      </div>
    </div>
  );
}

/* ═══════════════════════════════════════════════════════════════ stage brief */

function StageBrief({ stage, crypto, primitive }: { stage: AttackStage; crypto: ScenarioCryptoProfile; primitive?: ClassicalPrimitive }) {
  const accent = TENSE_COLOR[stage.tense];
  const rows: Array<{ label: string; body: string; tone: string }> = [
    { label: 'What happens', body: stage.action, tone: QSR.ink },
    { label: 'The mathematics', body: stage.mechanism, tone: QSR.inkSoft },
    { label: 'Why it works', body: stage.enabler, tone: QSR.inkSoft },
    { label: 'What stops it', body: stage.countermeasure, tone: QSR.safe },
  ];

  return (
    <AnimatePresence mode="wait">
      <motion.div
        key={stage.id}
        initial={{ opacity: 0, y: 10 }}
        animate={{ opacity: 1, y: 0 }}
        exit={{ opacity: 0, y: -8 }}
        transition={{ duration: 0.28 }}
        className="space-y-4"
      >
        <div>
          <div className="flex flex-wrap items-center gap-2">
            <span className="font-mono text-[10px] font-bold uppercase tracking-[0.2em]" style={{ color: accent }}>
              Stage {stage.ordinal} of 6 · {stage.label}
            </span>
            <span
              className="rounded-[3px] border px-1.5 py-[2px] font-mono text-[8.5px] font-bold uppercase tracking-[0.14em]"
              style={{ color: accent, borderColor: tint(accent, 0.32), background: tint(accent, 0.08) }}
            >
              {stage.tense === 'present' ? 'Happening today' : stage.tense === 'future' ? 'Requires a CRQC' : 'Remedy'}
            </span>
          </div>
          <h4 className="mt-1.5 text-lg font-bold leading-tight text-slate-100">{stage.title}</h4>
        </div>

        {rows.map((row) => (
          <div key={row.label}>
            <div className="mb-1 font-mono text-[9px] font-bold uppercase tracking-[0.18em]" style={{ color: QSR.inkFaint }}>
              {row.label}
            </div>
            <p className="text-[12.5px] leading-relaxed" style={{ color: row.tone }}>
              {row.body}
            </p>
          </div>
        ))}

        <div className="flex flex-wrap gap-1.5 border-t pt-3.5" style={{ borderColor: QSR.hairline }}>
          <Chip label="Protocol" value={crypto.protocol} />
          {primitive && <Chip label="Primitive" value={primitive.name} accent={VERDICT_COLOR[primitive.verdict]} />}
          {primitive && <Chip label="Verdict" value={VERDICT_LABEL[primitive.verdict]} accent={VERDICT_COLOR[primitive.verdict]} />}
          <Chip label="Group" value={namedGroup(crypto.groupId)?.name ?? '—'} accent={namedGroup(crypto.groupId)?.quantumBroken ? QSR.broken : QSR.quantum} />
        </div>
      </motion.div>
    </AnimatePresence>
  );
}

/* ═════════════════════════════════════════════════════════════════════ stage */

export interface SimulationRangeProps {
  scenario: Scenario;
  crypto: ScenarioCryptoProfile;
  primitive?: ClassicalPrimitive;
  stage: number;
  progress: number;
  running: boolean;
  budget: QveBudget;
  dpr: number;
  /** Real Born-rule distribution from the Shor lab, when one has been run. */
  distribution: Float64Array | null;
  qubits: number;
  resolved: boolean;
  onSelectScenario: (id: string) => void;
  onSelectStage: (ordinal: number) => void;
  onNext: () => void;
  onPrevious: () => void;
  onToggleRunning: () => void;
}

export default function SimulationRange(props: SimulationRangeProps) {
  const { scenario, crypto, primitive, stage, progress, running, budget, dpr, distribution, qubits, resolved } = props;
  const stageMeta = ATTACK_CHAIN[stage - 1];
  const group = namedGroup(crypto.groupId);
  const quantumSafe = group ? !group.quantumBroken : false;

  const sites: StageSites = {
    client: scenario.nodeNames.client,
    transit: scenario.nodeNames.gateway,
    server: scenario.nodeNames.server,
    archive: scenario.nodeNames.vault,
    crqc: 'CRQC Array',
  };

  const [webglReady, setWebglReady] = React.useState(false);
  const use3d = budget.core3d;

  return (
    <Panel
      accent={TENSE_COLOR[stageMeta.tense]}
      className="overflow-visible"
      bodyClassName="p-4 sm:p-5"
      eyebrow="Simulation range"
      title={scenario.name}
      subtitle={scenario.narrative}
      right={
        <div className="flex items-center gap-1.5">
          <button
            type="button"
            onClick={props.onPrevious}
            aria-label="Previous stage"
            className="rounded-md border p-2 transition-colors hover:border-cyan-400/40"
            style={{ borderColor: QSR.hairline, color: QSR.inkSoft }}
          >
            <SkipBack className="h-3.5 w-3.5" />
          </button>
          <button
            type="button"
            onClick={props.onToggleRunning}
            aria-label={running ? 'Pause simulation' : 'Play simulation'}
            className="rounded-md px-3 py-2 transition-transform hover:scale-105"
            style={{ background: running ? tint(QSR.live, 0.16) : QSR.live, color: running ? QSR.live : '#04060e' }}
          >
            {running ? <Pause className="h-3.5 w-3.5" /> : <Play className="h-3.5 w-3.5" />}
          </button>
          <button
            type="button"
            onClick={props.onNext}
            aria-label="Next stage"
            className="rounded-md border p-2 transition-colors hover:border-cyan-400/40"
            style={{ borderColor: QSR.hairline, color: QSR.inkSoft }}
          >
            <SkipForward className="h-3.5 w-3.5" />
          </button>
        </div>
      }
    >
      <div className="flex flex-col gap-4 lg:flex-row lg:items-start">
        <ScenarioSelector active={scenario} onSelect={props.onSelectScenario} />
        <div className="min-w-0 flex-1">
          <StageRail stage={stage} progress={progress} onSelect={props.onSelectStage} />
        </div>
      </div>

      <div className="mt-4 grid gap-4 xl:grid-cols-[minmax(0,1fr)_380px]">
        {/* ── The stage ──────────────────────────────────────────────── */}
        <div
          className="relative min-h-[420px] overflow-hidden rounded-xl border sm:min-h-[480px]"
          style={{ borderColor: QSR.hairline, background: 'radial-gradient(ellipse 80% 70% at 50% 40%, rgba(12,20,42,0.9), rgba(3,4,10,0.98))' }}
        >
          {use3d ? (
            <React.Suspense fallback={null}>
              <QuantumStage3D
                stage={stage}
                progress={progress}
                sites={sites}
                distribution={distribution}
                qubits={qubits}
                resolved={resolved}
                quantumSafe={quantumSafe}
                budget={budget}
                dpr={dpr}
                onReady={() => setWebglReady(true)}
              />
            </React.Suspense>
          ) : null}

          {/* The SVG stage holds the frame until WebGL is live, and IS the stage
              on devices that never get WebGL. */}
          {(!use3d || !webglReady) && (
            <div className="absolute inset-0">
              <StageFallback
                stage={stage}
                progress={progress}
                sites={sites}
                distribution={distribution}
                resolved={resolved}
                quantumSafe={quantumSafe}
                animate={budget.animate}
              />
            </div>
          )}

          {/* HUD */}
          <div className="pointer-events-none absolute inset-x-0 top-0 flex items-start justify-between gap-3 p-3.5">
            <div className="flex flex-wrap items-center gap-1.5">
              <span
                className="rounded-[3px] border px-1.5 py-[3px] font-mono text-[9px] font-bold uppercase tracking-[0.16em]"
                style={{ color: TENSE_COLOR[stageMeta.tense], borderColor: tint(TENSE_COLOR[stageMeta.tense], 0.3), background: 'rgba(4,7,16,0.75)' }}
              >
                {stageMeta.label}
              </span>
              <span
                className="rounded-[3px] border px-1.5 py-[3px] font-mono text-[9px] uppercase tracking-[0.14em]"
                style={{ color: QSR.inkMuted, borderColor: QSR.hairline, background: 'rgba(4,7,16,0.75)' }}
              >
                {use3d ? 'WebGL' : 'SVG'} stage
              </span>
            </div>
            <div className="text-right">
              <div className="font-mono text-[9px] uppercase tracking-[0.16em]" style={{ color: QSR.inkFaint }}>
                interference ring
              </div>
              <div className="flex items-center justify-end gap-1.5">
                <span className="font-mono text-[10px] font-bold" style={{ color: distribution ? (resolved ? QSR.quantum : QSR.live) : QSR.inkMuted }}>
                  {distribution ? `${qubits}-qubit register` : 'not yet run'}
                </span>
                {distribution && <ProvenanceBadge kind="measured" compact />}
              </div>
            </div>
          </div>

          <div className="pointer-events-none absolute inset-x-0 bottom-0 p-3.5">
            <p className="max-w-2xl text-[11px] leading-snug" style={{ color: QSR.inkMuted }}>
              The ring under the quantum core plots the real |ψ|² distribution from the state-vector simulator below. Everything
              else on this stage is staging.
            </p>
          </div>
        </div>

        {/* ── Mechanism brief ────────────────────────────────────────── */}
        <div className="rounded-xl border p-4" style={{ borderColor: QSR.hairline, background: 'rgba(4,7,16,0.5)' }}>
          <StageBrief stage={stageMeta} crypto={crypto} primitive={primitive} />
        </div>
      </div>

      <div className="mt-4 grid gap-3 md:grid-cols-2">
        <Callout tone="danger" title="Weakest link in this scenario">
          {crypto.weakestLink}
        </Callout>
        <Callout tone="warn" title={`Confidentiality shelf life — ${crypto.shelfLifeYears} years`}>
          {crypto.shelfLifeBasis}
        </Callout>
      </div>
    </Panel>
  );
}
