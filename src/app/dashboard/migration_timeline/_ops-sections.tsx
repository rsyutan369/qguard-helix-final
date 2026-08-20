'use client';

import { useEffect, useMemo, useRef, useState, type ReactNode } from 'react';
import { motion, AnimatePresence, useReducedMotion } from 'framer-motion';
import {
  Activity, AppWindow, ArrowRight, BadgeCheck, Boxes, Brain, ChevronDown, Cloud, Cpu,
  Database, Download, FileText, Globe2, KeyRound, Lock, Network, Play, RefreshCw, Rocket,
  Search, ShieldCheck, Sparkles, Zap, GitBranch, ScrollText, ListChecks, Layers, Gauge,
  CheckCircle2, XCircle, Clock3, Circle, ChevronRight, Filter, type LucideIcon,
} from 'lucide-react';
import { cn } from '@/lib/utils';
import { Panel, PanelHeader, Sparkline, RadialGauge, Bar, TONE, type Tone } from '../_components/executive/primitives';
import {
  CYAN, GREEN, RED, AMBER, TONE_HEX, numberFmt, pct, clampPct,
  depToneMeta, COMPLIANCE_STANDARDS, assetsToCsv, auditToCsv, downloadTextFile,
  type OpsTone, type BannerMetric, type OpsKpi, type MigrationWave, type PhaseGate,
  type TimelineCard, type DigitalTwinState, type LiveJob, type HealthMetric,
  type RiskBurndown, type AssetRow, type DepNode, type DepLink, type ActivityEvent,
  type AuditRow, type MigrationStatus,
} from './_ops-lib';

/* ------------------------------------------------------------------ */
/* Icon registry (derivations store icon names as strings)            */
/* ------------------------------------------------------------------ */

const ICONS: Record<string, LucideIcon> = {
  AppWindow, BadgeCheck, Network, Globe2, Lock, ShieldCheck, Cloud, Boxes, Cpu, KeyRound,
  FileText, Activity, Database, GitBranch,
};
function iconFor(name: string): LucideIcon {
  return ICONS[name] || Circle;
}

/* ------------------------------------------------------------------ */
/* Shared presentational primitives                                    */
/* ------------------------------------------------------------------ */

export function SectionCard({
  title, icon, live, right, children, className, id,
}: {
  title: string; icon?: LucideIcon; live?: boolean; right?: ReactNode;
  children: ReactNode; className?: string; id?: string;
}) {
  return (
    <Panel className={cn('p-5', className)}>
      <div id={id} className="scroll-mt-24" />
      <PanelHeader title={title} icon={icon} live={live} right={right} />
      {children}
    </Panel>
  );
}

function toneClasses(tone: OpsTone) {
  const t = TONE[tone as Tone];
  return { text: t.text, soft: t.soft, border: t.border, dot: t.dot, hex: TONE_HEX[tone] };
}

export function Chip({ children, tone = 'neutral', title }: { children: ReactNode; tone?: OpsTone; title?: string; key?: string | number }) {
  const t = toneClasses(tone);
  return (
    <span title={title} className={cn('inline-flex items-center gap-1 rounded-md border px-2 py-0.5 text-[9px] font-black uppercase tracking-wider', t.text, t.soft, t.border)}>
      {children}
    </span>
  );
}

/**
 * Animates a numeric value; renders non-numeric text verbatim.
 *
 * The count-up runs ONLY when the numeric target actually changes — never on
 * an unrelated re-render (e.g. the 8s scanner poll producing an identical
 * value). Without this guard the effect restarted every render and the numbers
 * appeared to run/flicker perpetually.
 */
export function AnimatedStat({ text, className }: { text: string; className?: string }) {
  const reduce = useReducedMotion();
  const parsed = useMemo(() => {
    const m = /^(-?[\d,]+\.?\d*)(\s?%|\/min|s|ms)?$/.exec(text.trim());
    if (!m) return null;
    return { target: Number(m[1].replace(/,/g, '')), suffix: m[2] ?? '', decimals: m[1].includes('.') ? 1 : 0 };
  }, [text]);

  const target = parsed && Number.isFinite(parsed.target) ? parsed.target : 0;
  const [display, setDisplay] = useState(target);
  const fromRef = useRef(target);

  useEffect(() => {
    if (!parsed || !Number.isFinite(parsed.target)) return;
    const to = parsed.target;
    const from = fromRef.current;
    if (reduce || from === to) { fromRef.current = to; setDisplay(to); return; }
    let raf = 0;
    const start = performance.now();
    const dur = 600;
    const tick = (now: number) => {
      const p = Math.min(1, (now - start) / dur);
      const eased = 1 - Math.pow(1 - p, 3);
      setDisplay(from + (to - from) * eased);
      if (p < 1) { raf = requestAnimationFrame(tick); }
      else { fromRef.current = to; setDisplay(to); }
    };
    raf = requestAnimationFrame(tick);
    return () => cancelAnimationFrame(raf);
    // Re-run strictly when the numeric target changes.
  }, [target, reduce]); // eslint-disable-line react-hooks/exhaustive-deps

  if (!parsed) return <span className={className}>{text}</span>;
  const shown = parsed.decimals ? display.toFixed(1) : Math.round(display).toLocaleString('en-US');
  return <span className={className}>{shown}{parsed.suffix}</span>;
}

const STATUS_META: Record<MigrationStatus, { label: string; tone: OpsTone; icon: LucideIcon }> = {
  completed: { label: 'Completed', tone: 'good', icon: CheckCircle2 },
  'in-progress': { label: 'In Progress', tone: 'neutral', icon: RefreshCw },
  scheduled: { label: 'Scheduled', tone: 'info', icon: Clock3 },
  pending: { label: 'Pending', tone: 'warning', icon: Circle },
  failed: { label: 'Failed', tone: 'critical', icon: XCircle },
};

/* ================================================================== */
/* 1 — Executive Summary Banner                                       */
/* ================================================================== */

export function ExecutiveBanner({ metrics }: { metrics: BannerMetric[] }) {
  return (
    <Panel className="relative overflow-hidden p-5">
      <div className="pointer-events-none absolute inset-0 bg-[radial-gradient(120%_120%_at_0%_0%,rgba(34,211,238,0.10),transparent_55%)]" />
      <div className="relative mb-4 flex items-center gap-2">
        <Rocket className="h-4 w-4 text-cyan-300" />
        <span className="text-[11px] font-black uppercase tracking-[0.18em] text-white/85">Executive Migration Summary</span>
        <span className="ml-auto text-[9px] font-mono uppercase tracking-widest text-white/30">CIO / CISO Snapshot</span>
      </div>
      <div className="relative grid grid-cols-2 gap-3 sm:grid-cols-3 lg:grid-cols-5 xl:grid-cols-9">
        {metrics.map((m) => {
          const t = toneClasses(m.tone);
          return (
            <div key={m.key} title={m.basis} className={cn('rounded-xl border bg-white/[0.02] p-3', t.border)}>
              <div className="text-[8.5px] font-black uppercase leading-tight tracking-wider text-white/45">{m.label}</div>
              <AnimatedStat text={m.value} className={cn('mt-1.5 block text-xl font-black leading-none', t.text)} />
              <div className="mt-1.5 flex items-center gap-1">
                <span className={cn('h-1 w-1 rounded-full', t.dot)} />
                <span className="truncate text-[8px] font-semibold text-white/35">{m.basis}</span>
              </div>
            </div>
          );
        })}
      </div>
    </Panel>
  );
}

/* ================================================================== */
/* 2 — Mission Control KPI Header                                      */
/* ================================================================== */

export function KpiHeader({ kpis }: { kpis: OpsKpi[] }) {
  return (
    <div className="grid grid-cols-2 gap-3 sm:grid-cols-3 lg:grid-cols-4 xl:grid-cols-5">
      {kpis.map((kpi) => {
        const t = toneClasses(kpi.tone);
        return (
          <Panel key={kpi.key} className="group/kpi p-4">
            <div title={kpi.basis} className="flex items-start justify-between gap-2">
              <div className="min-w-0">
                <div className="truncate text-[8.5px] font-black uppercase tracking-wider text-white/45">{kpi.label}</div>
                <AnimatedStat text={kpi.value} className="mt-2 block text-2xl font-black leading-none text-white" />
                <div className={cn('mt-1 truncate text-[9px] font-bold', t.text)}>{kpi.detail}</div>
              </div>
              {kpi.live && (
                <span className="flex shrink-0 items-center gap-1 text-[7px] font-black uppercase tracking-widest text-emerald-400">
                  <span className="h-1.5 w-1.5 animate-pulse rounded-full bg-emerald-400 shadow-[0_0_8px_rgba(52,211,153,0.8)]" />
                </span>
              )}
            </div>
            <div className="mt-2 h-[34px] opacity-80 transition-opacity group-hover/kpi:opacity-100">
              <Sparkline values={kpi.spark.length > 1 ? kpi.spark : [0, kpi.spark[0] ?? 0]} color={t.hex} />
            </div>
          </Panel>
        );
      })}
    </div>
  );
}

/* ================================================================== */
/* 3 — Migration Wave Overview                                        */
/* ================================================================== */

const WAVE_STATUS_TONE: Record<MigrationWave['status'], OpsTone> = {
  completed: 'good', running: 'neutral', scheduled: 'info', empty: 'warning',
};

export function WaveOverview({ waves, activeId }: { waves: MigrationWave[]; activeId: number | null }) {
  const [expanded, setExpanded] = useState<number | null>(activeId);
  return (
    <SectionCard title="Migration Wave Overview" icon={Layers} right={<span className="text-[9px] font-mono uppercase tracking-widest text-white/30">{waves.length} waves</span>}>
      <div className="grid grid-cols-1 gap-3 lg:grid-cols-3">
        {waves.map((wave) => {
          const tone = WAVE_STATUS_TONE[wave.status];
          const t = toneClasses(tone);
          const open = expanded === wave.id;
          const isActive = wave.id === activeId;
          return (
            <div key={wave.id} className={cn('rounded-xl border bg-white/[0.02] transition-all', isActive ? 'border-cyan-400/40 shadow-[0_0_24px_rgba(34,211,238,0.12)]' : 'border-white/10')}>
              <button type="button" onClick={() => setExpanded(open ? null : wave.id)} className="flex w-full items-center justify-between gap-3 p-4 text-left">
                <div className="min-w-0">
                  <div className="flex items-center gap-2">
                    <span className="text-sm font-black text-white">{wave.name}</span>
                    <Chip tone={tone}>{wave.status === 'empty' ? 'No Evidence' : wave.status}</Chip>
                    {isActive && <Chip tone="neutral">Active</Chip>}
                  </div>
                  <div className="mt-0.5 truncate text-[10px] font-semibold text-white/40">{wave.theme}</div>
                </div>
                <ChevronDown className={cn('h-4 w-4 shrink-0 text-white/40 transition-transform', open && 'rotate-180')} />
              </button>
              <div className="px-4 pb-2">
                <div className="flex items-center justify-between text-[9px] font-bold uppercase tracking-wider text-white/40">
                  <span>{numberFmt(wave.ready)} / {numberFmt(wave.total)} ready</span>
                  <span className={t.text}>{pct(wave.progress)}</span>
                </div>
                <div className="mt-1.5"><Bar value={wave.progress} color={t.hex} /></div>
              </div>
              <AnimatePresence initial={false}>
                {open && (
                  <motion.div initial={{ height: 0, opacity: 0 }} animate={{ height: 'auto', opacity: 1 }} exit={{ height: 0, opacity: 0 }} className="overflow-hidden">
                    <div className="space-y-2 border-t border-white/10 p-4">
                      <div className="mb-1 text-[8.5px] font-black uppercase tracking-wider text-white/35">Window · {wave.window}</div>
                      {wave.categories.map((cat) => {
                        const Icon = iconFor(cat.icon);
                        return (
                          <div key={cat.key} className="flex items-center gap-3">
                            <Icon className="h-3.5 w-3.5 shrink-0 text-cyan-300/70" />
                            <span className="w-28 shrink-0 truncate text-[10px] font-bold text-white/70">{cat.label}</span>
                            <div className="flex-1"><Bar value={cat.progress} color={cat.status === 'completed' ? GREEN : cat.status === 'empty' ? 'rgba(255,255,255,0.2)' : CYAN} height={4} /></div>
                            <span className="w-16 shrink-0 text-right text-[9px] font-mono text-white/45">{numberFmt(cat.total)} comp</span>
                          </div>
                        );
                      })}
                    </div>
                  </motion.div>
                )}
              </AnimatePresence>
            </div>
          );
        })}
      </div>
    </SectionCard>
  );
}

/* ================================================================== */
/* 4 — Interactive NIST Phase Gates                                   */
/* ================================================================== */

const GATE_STATUS: Record<PhaseGate['status'], { tone: OpsTone; icon: LucideIcon }> = {
  complete: { tone: 'good', icon: CheckCircle2 },
  active: { tone: 'neutral', icon: RefreshCw },
  pending: { tone: 'warning', icon: Circle },
  blocked: { tone: 'critical', icon: XCircle },
};

export function PhaseGates({ gates }: { gates: PhaseGate[] }) {
  const [open, setOpen] = useState<string | null>(gates.find((g) => g.status === 'active')?.id ?? null);
  return (
    <SectionCard title="Interactive NIST Phase Gates" icon={ListChecks} right={<span className="text-[9px] font-mono uppercase tracking-widest text-white/30">{gates.filter((g) => g.status === 'complete').length}/{gates.length} cleared</span>}>
      <div className="space-y-2">
        {gates.map((gate, idx) => {
          const meta = GATE_STATUS[gate.status];
          const t = toneClasses(meta.tone);
          const isOpen = open === gate.id;
          const Icon = meta.icon;
          return (
            <div key={gate.id} className={cn('rounded-xl border bg-white/[0.02]', t.border)}>
              <button type="button" onClick={() => setOpen(isOpen ? null : gate.id)} className="grid w-full grid-cols-[auto_1fr_auto] items-center gap-3 p-3 text-left">
                <div className={cn('grid h-8 w-8 place-items-center rounded-full border', t.border, t.soft)}>
                  <Icon className={cn('h-4 w-4', t.text, gate.status === 'active' && 'animate-spin')} />
                </div>
                <div className="min-w-0">
                  <div className="flex items-center gap-2">
                    <span className="text-[8px] font-mono text-white/30">{String(idx + 1).padStart(2, '0')}</span>
                    <span className="truncate text-xs font-black uppercase tracking-wide text-white/85">{gate.label}</span>
                    <Chip tone={meta.tone}>{gate.status}</Chip>
                  </div>
                  <div className="mt-1 flex items-center gap-2">
                    <div className="h-1 w-24 overflow-hidden rounded-full bg-white/10"><div className="h-full rounded-full" style={{ width: `${gate.progress}%`, backgroundColor: t.hex }} /></div>
                    <span className="truncate text-[9px] font-semibold text-white/40">{gate.kpi}</span>
                  </div>
                </div>
                <ChevronDown className={cn('h-4 w-4 text-white/40 transition-transform', isOpen && 'rotate-180')} />
              </button>
              <AnimatePresence initial={false}>
                {isOpen && (
                  <motion.div initial={{ height: 0, opacity: 0 }} animate={{ height: 'auto', opacity: 1 }} exit={{ height: 0, opacity: 0 }} className="overflow-hidden">
                    <div className="grid grid-cols-1 gap-3 border-t border-white/10 p-4 md:grid-cols-2 lg:grid-cols-3">
                      <GateField label="Deliverables">{gate.deliverables.map((d) => <div key={d} className="text-[10px] text-white/60">• {d}</div>)}</GateField>
                      <GateField label="Owner / Duration"><div className="text-[10px] text-white/60">{gate.owner}</div><div className="text-[10px] text-white/40">{gate.estDuration} · {pct(gate.progress)}</div></GateField>
                      <GateField label="Evidence"><div className="text-[10px] text-white/60">{gate.detail}</div></GateField>
                      <GateField label="Validation / Rollback"><div className="text-[10px] text-white/60">{gate.validation}</div><div className="text-[10px] text-white/40">{gate.rollback}</div></GateField>
                      <GateField label="Telemetry"><div className="text-[10px] text-white/60">{gate.telemetry}</div></GateField>
                      <GateField label="Policies">
                        <div className="flex flex-wrap gap-1">{gate.standards.map((s) => <Chip key={s} tone="info">{s}</Chip>)}</div>
                      </GateField>
                      <div className="md:col-span-2 lg:col-span-3">
                        <a href={gate.route} className="inline-flex items-center gap-1 rounded-lg border border-cyan-400/30 bg-cyan-500/10 px-3 py-1.5 text-[9px] font-black uppercase tracking-wider text-cyan-300 transition hover:bg-cyan-500/20">
                          Open owning module <ArrowRight className="h-3 w-3" />
                        </a>
                      </div>
                    </div>
                  </motion.div>
                )}
              </AnimatePresence>
            </div>
          );
        })}
      </div>
    </SectionCard>
  );
}

function GateField({ label, children }: { label: string; children: ReactNode }) {
  return (
    <div className="rounded-lg border border-white/5 bg-black/20 p-2.5">
      <div className="mb-1 text-[8px] font-black uppercase tracking-widest text-cyan-300/70">{label}</div>
      {children}
    </div>
  );
}

/* ================================================================== */
/* 5 — Enterprise Timeline Cards                                      */
/* ================================================================== */

const TIMELINE_FILTERS: Array<{ label: string; value: MigrationStatus | 'all' }> = [
  { label: 'All', value: 'all' }, { label: 'In Progress', value: 'in-progress' },
  { label: 'Scheduled', value: 'scheduled' }, { label: 'Completed', value: 'completed' },
  { label: 'Pending', value: 'pending' }, { label: 'Failed', value: 'failed' },
];

export function TimelineSection({ cards, onSelect }: { cards: TimelineCard[]; onSelect: (id: string) => void }) {
  const [filter, setFilter] = useState<MigrationStatus | 'all'>('all');
  const filtered = cards.filter((c) => filter === 'all' || c.status === filter);
  return (
    <SectionCard
      title="Migration Timeline"
      icon={GitBranch}
      right={
        <div className="flex flex-wrap gap-1">
          {TIMELINE_FILTERS.map((f) => (
            <button key={f.value} type="button" onClick={() => setFilter(f.value)} className={cn('rounded-md border px-2 py-1 text-[8.5px] font-black uppercase tracking-wider transition', filter === f.value ? 'border-cyan-400/60 bg-cyan-500/10 text-cyan-300' : 'border-white/10 text-white/40 hover:text-white/70')}>{f.label}</button>
          ))}
        </div>
      }
    >
      <div className="relative space-y-3">
        <div className="absolute bottom-4 left-[19px] top-2 w-px bg-gradient-to-b from-cyan-400/60 via-cyan-400/20 to-transparent" />
        {filtered.length === 0 ? (
          <div className="py-10 text-center text-[10px] font-black uppercase tracking-widest text-white/30">No migrations match this filter.</div>
        ) : filtered.map((card, i) => {
          const meta = STATUS_META[card.status];
          const t = toneClasses(meta.tone);
          const Icon = meta.icon;
          return (
            <motion.button
              type="button"
              key={card.id}
              onClick={() => onSelect(card.id)}
              initial={{ opacity: 0, x: -12 }}
              animate={{ opacity: 1, x: 0 }}
              transition={{ delay: i * 0.03 }}
              className="grid w-full grid-cols-[40px_1fr] gap-3 text-left"
            >
              <div className="relative flex justify-center pt-2">
                <div className={cn('z-10 grid h-10 w-10 place-items-center rounded-full border bg-[#0b1120]', t.border, t.soft, t.text)}>
                  <Icon className={cn('h-4 w-4', card.status === 'in-progress' && 'animate-spin')} />
                </div>
              </div>
              <div className={cn('rounded-xl border bg-white/[0.02] p-3 transition hover:border-cyan-400/40 hover:bg-white/[0.04]', t.border)}>
                <div className="flex flex-wrap items-center gap-2">
                  <span className="text-sm font-black text-white">{card.title}</span>
                  <Chip tone={meta.tone}>{meta.label}</Chip>
                  <Chip tone={card.priority === 'Critical' ? 'critical' : card.priority === 'High' ? 'warning' : 'neutral'}>{card.priority}</Chip>
                  <Chip tone="info">{card.wave}</Chip>
                  <span className="ml-auto text-[9px] font-mono text-white/35">{card.date}</span>
                </div>
                <p className="mt-1 text-[11px] font-semibold leading-relaxed text-white/45">{card.description}</p>
                <div className="mt-2 grid grid-cols-2 gap-x-4 gap-y-1 text-[9px] font-semibold sm:grid-cols-4">
                  <Field label="Owner" value={card.owner} />
                  <Field label="Assets" value={numberFmt(card.assets)} />
                  <Field label="Downtime" value={card.downtime} tone="good" />
                  <Field label="Confidence" value={pct(card.confidence)} tone="neutral" />
                  <Field label="Digital Twin" value={card.digitalTwin} tone={card.digitalTwin === 'PASS' ? 'good' : card.digitalTwin === 'REVIEW' ? 'warning' : 'info'} />
                  <Field label="Validation" value={card.validation} />
                  <Field label="Scanner" value={card.scannerEvidence} />
                  <Field label="Mapped" value={card.policy[0]} tone="info" />
                </div>
                {card.status === 'in-progress' && (
                  <div className="mt-2 flex items-center gap-2">
                    <div className="h-1.5 flex-1"><Bar value={card.progress} color={CYAN} height={6} /></div>
                    <span className="text-[10px] font-black text-white">{pct(card.progress)}</span>
                  </div>
                )}
              </div>
            </motion.button>
          );
        })}
      </div>
    </SectionCard>
  );
}

function Field({ label, value, tone = 'neutral' }: { label: string; value: string; tone?: OpsTone }) {
  const t = toneClasses(tone);
  return (
    <div className="min-w-0">
      <span className="text-white/30">{label}: </span>
      <span className={cn('truncate font-bold', tone === 'neutral' ? 'text-white/70' : t.text)}>{value}</span>
    </div>
  );
}

/* ================================================================== */
/* 6 — Digital Twin                                                   */
/* ================================================================== */

export function DigitalTwinPanel({ twin }: { twin: DigitalTwinState }) {
  const metrics: Array<[string, string, OpsTone]> = [
    ['Clone Fidelity', pct(twin.cloneFidelity), 'neutral'],
    ['Simulation Accuracy', pct(twin.simulationAccuracy), 'good'],
    ['Predicted Failures', numberFmt(twin.predictedFailures), twin.predictedFailures > 0 ? 'warning' : 'good'],
    ['Dependencies Modeled', numberFmt(twin.dependenciesModeled), 'info'],
    ['Rollback Snapshots', numberFmt(twin.rollbackSnapshots), 'neutral'],
    ['Isolation Verified', twin.isolationVerified ? 'Yes' : 'No', twin.isolationVerified ? 'good' : 'warning'],
  ];
  return (
    <SectionCard
      title="Digital Twin Simulation"
      icon={Brain}
      live={twin.status === 'running'}
      right={<Chip tone={twin.status === 'running' ? 'neutral' : twin.status === 'ready' ? 'good' : 'warning'}>{twin.status}</Chip>}
    >
      <div className="flex flex-col gap-4 lg:flex-row lg:items-center">
        <div className="flex items-center gap-4">
          <RadialGauge value={twin.confidence} color={CYAN} size={92} label={`${clampPct(twin.confidence)}%`} sublabel="confidence" />
          <div className="text-[10px] font-semibold text-white/45">
            <div className="max-w-[160px]">{twin.basis}</div>
            <div className="mt-1 text-white/30">Full simulation runs in Migration Sandbox.</div>
          </div>
        </div>
        <div className="grid flex-1 grid-cols-2 gap-2 sm:grid-cols-3">
          {metrics.map(([label, value, tone]) => {
            const t = toneClasses(tone);
            return (
              <div key={label} className="rounded-lg border border-white/5 bg-black/20 p-2.5">
                <div className="text-[8px] font-black uppercase tracking-wider text-white/40">{label}</div>
                <div className={cn('mt-1 text-base font-black', t.text)}>{value}</div>
              </div>
            );
          })}
        </div>
      </div>
      <div className="mt-4 flex flex-wrap gap-2">
        <TwinButton href="/dashboard/migration-sandbox" icon={Play} primary>Run Simulation</TwinButton>
        <TwinButton href="/dashboard/migration-sandbox" icon={FileText}>View Results</TwinButton>
        <TwinButton href="/dashboard/migration-sandbox" icon={GitBranch}>Compare Scenarios</TwinButton>
        <TwinButton href="/dashboard/migration-intelligence" icon={RefreshCw}>Recalculate</TwinButton>
      </div>
    </SectionCard>
  );
}

function TwinButton({ href, icon: Icon, children, primary }: { href: string; icon: LucideIcon; children: ReactNode; primary?: boolean }) {
  return (
    <a href={href} className={cn('inline-flex items-center gap-1.5 rounded-lg border px-3 py-1.5 text-[9px] font-black uppercase tracking-wider transition', primary ? 'border-cyan-400/50 bg-cyan-500/15 text-cyan-200 hover:bg-cyan-500/25' : 'border-white/10 bg-white/5 text-white/60 hover:border-cyan-400/30 hover:text-cyan-300')}>
      <Icon className="h-3.5 w-3.5" />{children}
    </a>
  );
}

/* ================================================================== */
/* 7 — Live Migration Telemetry                                       */
/* ================================================================== */

const HEALTH_TONE: Record<LiveJob['health'], OpsTone> = { healthy: 'good', degraded: 'warning', failed: 'critical', queued: 'info' };

export function LiveTelemetry({ jobs, live, onSelect }: { jobs: LiveJob[]; live: boolean; onSelect: (id: string) => void }) {
  return (
    <SectionCard title="Real-Time Migration Telemetry" icon={Activity} live={live} right={<span className="text-[9px] font-mono uppercase tracking-widest text-white/30">{jobs.length} jobs</span>}>
      <div className="-mx-1 overflow-x-auto">
        <table className="w-full min-w-[900px] text-left">
          <thead className="border-b border-white/10 text-[8px] font-black uppercase tracking-widest text-cyan-300/70">
            <tr>
              {['Job', 'Asset', 'Business Unit', 'Current → Target', 'Migration', 'Validation', 'State', 'Latency', 'Duration', 'Operator', 'Retry', 'Health'].map((h) => (
                <th key={h} className="whitespace-nowrap px-2 py-2">{h}</th>
              ))}
            </tr>
          </thead>
          <tbody className="divide-y divide-white/5 text-[10px] font-semibold text-white/60">
            {jobs.length === 0 ? (
              <tr><td colSpan={12} className="py-8 text-center text-white/30">No active migration jobs. Telemetry appears as jobs are scheduled.</td></tr>
            ) : jobs.map((job) => {
              const t = toneClasses(HEALTH_TONE[job.health]);
              return (
                <tr key={job.id} onClick={() => onSelect(job.id)} className="cursor-pointer transition hover:bg-cyan-500/[0.05]">
                  <td className="whitespace-nowrap px-2 py-2 font-mono text-white/75">{job.id}</td>
                  <td className="max-w-[140px] truncate px-2 py-2 text-white/80">{job.asset}</td>
                  <td className="max-w-[110px] truncate px-2 py-2">{job.businessUnit}</td>
                  <td className="whitespace-nowrap px-2 py-2 font-mono text-[9px] text-white/50">{job.currentAlgo} → {job.targetAlgo}</td>
                  <td className="px-2 py-2">
                    <div className="flex items-center gap-1.5">
                      <div className="h-1 w-14"><Bar value={job.migrationPct} color={CYAN} height={4} /></div>
                      <span className="w-8 text-[9px]">{pct(job.migrationPct)}</span>
                    </div>
                  </td>
                  <td className="px-2 py-2">{pct(job.validationPct)}</td>
                  <td className="whitespace-nowrap px-2 py-2 uppercase text-white/55">{String(job.phase).replace('_', ' ')}</td>
                  <td className="px-2 py-2">{job.latency}</td>
                  <td className="px-2 py-2">{job.duration}</td>
                  <td className="max-w-[90px] truncate px-2 py-2 font-mono text-[9px]">{job.operator}</td>
                  <td className="px-2 py-2">{job.retryCount}</td>
                  <td className="px-2 py-2"><span className={cn('inline-flex items-center gap-1 font-black uppercase', t.text)}><span className={cn('h-1.5 w-1.5 rounded-full', t.dot)} />{job.health}</span></td>
                </tr>
              );
            })}
          </tbody>
        </table>
      </div>
    </SectionCard>
  );
}

/* ================================================================== */
/* 8 — AI Recommendations (Sophia)                                    */
/* ================================================================== */

export interface OpsRecommendation {
  id: string; priority: number; category: string; title: string; description: string;
  action: string; estimatedEffort: string; assetId: string | null; route: string;
}

export function AiRecommendationsPanel({
  recs, loading, dismissed, onDismiss, onExplain,
}: {
  recs: OpsRecommendation[]; loading: boolean; dismissed: Set<string>;
  onDismiss: (id: string) => void; onExplain: (rec: OpsRecommendation) => void;
}) {
  const visible = recs.filter((r) => !dismissed.has(r.id));
  return (
    <SectionCard title="Sophia AI Recommendations" icon={Sparkles} right={<Chip tone="ai">{visible.length} active</Chip>}>
      {loading ? (
        <div className="space-y-2">{[0, 1, 2].map((i) => <div key={i} className="h-16 animate-pulse rounded-lg bg-white/5" />)}</div>
      ) : visible.length === 0 ? (
        <div className="rounded-lg border border-emerald-500/20 bg-emerald-500/[0.06] p-6 text-center">
          <ShieldCheck className="mx-auto h-6 w-6 text-emerald-400" />
          <div className="mt-2 text-[11px] font-black uppercase tracking-wider text-emerald-300">No open recommendations</div>
          <div className="mt-1 text-[10px] text-white/40">Sophia continuously analyzes migration evidence.</div>
        </div>
      ) : (
        <div className="space-y-2">
          {visible.slice(0, 6).map((rec) => {
            const tone: OpsTone = rec.priority <= 1 ? 'critical' : rec.priority === 2 ? 'warning' : 'ai';
            const t = toneClasses(tone);
            return (
              <div key={rec.id} className={cn('rounded-xl border bg-white/[0.02] p-3', t.border)}>
                <div className="flex items-start gap-2">
                  <div className={cn('grid h-7 w-7 shrink-0 place-items-center rounded-lg', t.soft)}><Zap className={cn('h-3.5 w-3.5', t.text)} /></div>
                  <div className="min-w-0 flex-1">
                    <div className="flex flex-wrap items-center gap-2">
                      <span className="text-xs font-black text-white/90">{rec.title}</span>
                      <Chip tone={tone}>{rec.priority <= 1 ? 'Critical' : rec.priority === 2 ? 'High' : 'Medium'}</Chip>
                      <Chip tone="neutral">{rec.category}</Chip>
                    </div>
                    <p className="mt-1 text-[10px] font-semibold leading-relaxed text-white/45">{rec.description}</p>
                    <div className="mt-1 flex flex-wrap items-center gap-3 text-[9px] font-bold text-white/40">
                      <span>Effort: <span className="text-white/60">{rec.estimatedEffort}</span></span>
                      <span>Action: <span className="text-cyan-300">{rec.action}</span></span>
                    </div>
                    <div className="mt-2 flex flex-wrap gap-1.5">
                      <a href={rec.route} className="rounded-md border border-cyan-400/40 bg-cyan-500/15 px-2.5 py-1 text-[8.5px] font-black uppercase tracking-wider text-cyan-200 transition hover:bg-cyan-500/25">Apply</a>
                      <a href={rec.route} className="rounded-md border border-white/10 bg-white/5 px-2.5 py-1 text-[8.5px] font-black uppercase tracking-wider text-white/60 transition hover:text-white">Schedule</a>
                      <button type="button" onClick={() => onExplain(rec)} className="rounded-md border border-white/10 bg-white/5 px-2.5 py-1 text-[8.5px] font-black uppercase tracking-wider text-white/60 transition hover:text-white">Explain</button>
                      <button type="button" onClick={() => onDismiss(rec.id)} className="rounded-md border border-white/10 bg-white/5 px-2.5 py-1 text-[8.5px] font-black uppercase tracking-wider text-white/40 transition hover:text-red-300">Ignore</button>
                    </div>
                  </div>
                </div>
              </div>
            );
          })}
        </div>
      )}
    </SectionCard>
  );
}

/* ================================================================== */
/* 9 — Migration Health                                               */
/* ================================================================== */

export function HealthDashboard({ metrics, score }: { metrics: HealthMetric[]; score: number }) {
  return (
    <SectionCard title="Migration Health" icon={Gauge}>
      <div className="flex flex-col gap-4 lg:flex-row lg:items-center">
        <div className="flex shrink-0 items-center gap-3">
          <RadialGauge value={score} color={score >= 66 ? GREEN : score >= 33 ? CYAN : RED} size={96} label={`${clampPct(score)}%`} sublabel="health" />
        </div>
        <div className="grid flex-1 grid-cols-2 gap-2 sm:grid-cols-3 lg:grid-cols-5">
          {metrics.map((m) => {
            const t = toneClasses(m.tone);
            return (
              <div key={m.label} className="rounded-lg border border-white/5 bg-black/20 p-2.5">
                <div className="text-[8px] font-black uppercase leading-tight tracking-wider text-white/40">{m.label}</div>
                <div className={cn('mt-1 text-sm font-black', t.text)}>{m.value}</div>
                <div className="mt-1.5"><Bar value={m.pct} color={t.hex} height={3} /></div>
              </div>
            );
          })}
        </div>
      </div>
    </SectionCard>
  );
}

/* ================================================================== */
/* 10 — Risk Burn-down                                                */
/* ================================================================== */

export function RiskBurndownPanel({ data }: { data: RiskBurndown }) {
  const series = data.series;
  const all = [...series.critical, ...series.high, ...series.medium, ...series.resolved];
  const max = Math.max(1, ...all);
  const line = (values: number[]) => values.map((v, i) => {
    const x = (i / Math.max(1, values.length - 1)) * 100;
    const y = 100 - (v / max) * 88;
    return `${i === 0 ? 'M' : 'L'} ${x.toFixed(1)} ${y.toFixed(1)}`;
  }).join(' ');
  const hasSeries = series.critical.length > 1;
  return (
    <SectionCard title="Risk Burn-down" icon={Activity} right={<Chip tone={data.trend === 'down' ? 'good' : data.trend === 'up' ? 'critical' : 'neutral'}>{data.trend === 'down' ? `▼ ${data.resolved} resolved` : data.trend === 'up' ? `▲ ${data.added} new` : 'stable'}</Chip>}>
      <div className="grid grid-cols-3 gap-2 sm:grid-cols-6">
        {data.buckets.map((b) => {
          const t = toneClasses(b.tone);
          return (
            <div key={b.label} className={cn('rounded-lg border bg-white/[0.02] p-2 text-center', t.border)}>
              <div className={cn('text-lg font-black', t.text)}>{numberFmt(b.count)}</div>
              <div className="text-[8px] font-black uppercase tracking-wider text-white/40">{b.label}</div>
            </div>
          );
        })}
      </div>
      <div className="mt-4">
        {hasSeries ? (
          <>
            <div className="mb-2 flex flex-wrap gap-3 text-[9px] font-bold uppercase tracking-wider text-white/40">
              <Legend color={RED} label="Critical" /><Legend color={AMBER} label="High" /><Legend color={CYAN} label="Medium" /><Legend color={GREEN} label="Resolved" />
            </div>
            <svg viewBox="0 0 100 100" className="h-40 w-full overflow-visible" preserveAspectRatio="none">
              {[0, 25, 50, 75, 100].map((l) => <line key={l} x1="0" x2="100" y1={l} y2={l} stroke="rgba(255,255,255,0.06)" strokeDasharray="1 2" />)}
              <path d={line(series.critical)} fill="none" stroke={RED} strokeWidth="1.6" vectorEffect="non-scaling-stroke" />
              <path d={line(series.high)} fill="none" stroke={AMBER} strokeWidth="1.6" vectorEffect="non-scaling-stroke" />
              <path d={line(series.medium)} fill="none" stroke={CYAN} strokeWidth="1.6" vectorEffect="non-scaling-stroke" />
              <path d={line(series.resolved)} fill="none" stroke={GREEN} strokeWidth="1.6" vectorEffect="non-scaling-stroke" />
            </svg>
            <div className="mt-1 flex justify-between text-[9px] font-bold text-white/30"><span>Oldest scan</span><span>Latest scan</span></div>
          </>
        ) : (
          <div className="rounded-lg border border-white/5 bg-black/20 p-6 text-center text-[10px] font-black uppercase tracking-widest text-white/30">Run more scans to build a burn-down trend.</div>
        )}
      </div>
    </SectionCard>
  );
}

function Legend({ color, label }: { color: string; label: string }) {
  return <span className="flex items-center gap-1.5"><span className="h-2 w-2 rounded-full" style={{ backgroundColor: color }} />{label}</span>;
}

/* ================================================================== */
/* 12 — Dependency Graph                                              */
/* ================================================================== */

export function DependencyGraphPanel({
  graph, onSelectNode,
}: {
  graph: { nodes: DepNode[]; links: DepLink[] }; onSelectNode: (id: string) => void;
}) {
  const [view, setView] = useState<'graph' | 'list'>('graph');
  const nodeMap = useMemo(() => new Map(graph.nodes.map((n) => [n.id, n])), [graph.nodes]);
  const pathFor = (from: DepNode, to: DepNode) => {
    const midY = (from.y + to.y) / 2;
    return `M ${from.x} ${from.y} C ${from.x} ${midY}, ${to.x} ${midY}, ${to.x} ${to.y}`;
  };
  return (
    <SectionCard
      title="Migration Dependency Graph"
      icon={Network}
      right={
        <div className="inline-flex rounded-lg border border-white/10 bg-black/20 p-0.5">
          {(['graph', 'list'] as const).map((v) => (
            <button key={v} type="button" onClick={() => setView(v)} className={cn('rounded-md px-3 py-1 text-[8.5px] font-black uppercase tracking-wider transition', view === v ? 'bg-cyan-500/15 text-cyan-300' : 'text-white/40 hover:text-white/70')}>{v}</button>
          ))}
        </div>
      }
    >
      {view === 'graph' ? (
        <div className="overflow-x-auto">
          <div className="relative h-[380px] min-w-[820px] rounded-xl border border-white/10 bg-[#070b18]/40">
            <svg className="absolute inset-0 h-full w-full" viewBox="0 0 100 100" preserveAspectRatio="none" aria-hidden="true">
              <defs>
                {(['strong', 'weak', 'at-risk', 'blocked'] as const).map((tone) => (
                  <marker key={tone} id={`dep-arrow-${tone}`} markerWidth="6" markerHeight="6" refX="5.4" refY="3" orient="auto"><path d="M0,0 L6,3 L0,6 Z" fill={depToneMeta(tone).color} /></marker>
                ))}
              </defs>
              {graph.links.map((link) => {
                const from = nodeMap.get(link.from); const to = nodeMap.get(link.to);
                if (!from || !to) return null;
                return <path key={`${link.from}-${link.to}`} d={pathFor(from, to)} fill="none" stroke={depToneMeta(link.tone).color} strokeWidth="0.6" markerEnd={`url(#dep-arrow-${link.tone})`} vectorEffect="non-scaling-stroke" opacity="0.8" />;
              })}
            </svg>
            {graph.nodes.map((node) => {
              const Icon = iconFor(node.icon); const meta = depToneMeta(node.tone);
              return (
                <button key={node.id} type="button" onClick={() => onSelectNode(node.id)} className="absolute flex -translate-x-1/2 -translate-y-1/2 items-center gap-2 transition hover:scale-105" style={{ left: `${node.x}%`, top: `${node.y}%` }}>
                  <span className="grid h-10 w-10 place-items-center rounded-full border-2 bg-[#0b1120]" style={{ borderColor: meta.color, boxShadow: `0 0 18px ${meta.color}55` }}><Icon className="h-4 w-4" style={{ color: meta.color }} /></span>
                  <span className="min-w-max text-left">
                    <span className="block text-[10px] font-black text-white/85">{node.label}</span>
                    <span className="block text-[8px] font-bold uppercase tracking-wider" style={{ color: meta.color }}>{node.detail}</span>
                  </span>
                </button>
              );
            })}
            <div className="absolute inset-x-0 bottom-0 flex flex-wrap justify-center gap-6 border-t border-white/10 bg-black/20 px-4 py-2">
              {(['strong', 'weak', 'at-risk', 'blocked'] as const).map((tone) => {
                const meta = depToneMeta(tone);
                return <span key={tone} className="flex items-center gap-1.5 text-[8px] font-black uppercase tracking-wider text-white/50"><span className="h-1 w-8 rounded-full" style={{ backgroundColor: meta.color }} />{meta.label}</span>;
              })}
            </div>
          </div>
        </div>
      ) : (
        <div className="overflow-x-auto">
          <table className="w-full min-w-[720px] text-left">
            <thead className="border-b border-white/10 text-[8px] font-black uppercase tracking-widest text-cyan-300/70">
              <tr>{['Node', 'Status', 'Blast Radius', 'Risk', 'Order', 'Algorithms'].map((h) => <th key={h} className="px-2 py-2">{h}</th>)}</tr>
            </thead>
            <tbody className="divide-y divide-white/5 text-[10px] font-semibold text-white/60">
              {graph.nodes.map((node) => {
                const meta = depToneMeta(node.tone);
                return (
                  <tr key={node.id} onClick={() => onSelectNode(node.id)} className="cursor-pointer transition hover:bg-cyan-500/[0.05]">
                    <td className="px-2 py-2 text-white/80">{node.label}</td>
                    <td className="px-2 py-2 font-black" style={{ color: meta.color }}>{meta.label}</td>
                    <td className="px-2 py-2">{node.blastRadius} systems</td>
                    <td className="px-2 py-2">{node.risk}/100</td>
                    <td className="px-2 py-2">#{node.migrationOrder}</td>
                    <td className="px-2 py-2 font-mono text-[9px] text-white/45">{node.algorithms}</td>
                  </tr>
                );
              })}
            </tbody>
          </table>
        </div>
      )}
    </SectionCard>
  );
}

/* ================================================================== */
/* 13 — Live Activity Feed                                            */
/* ================================================================== */

export function ActivityFeed({ events }: { events: ActivityEvent[] }) {
  const scrollRef = useRef<HTMLDivElement>(null);
  const [paused, setPaused] = useState(false);
  useEffect(() => {
    if (paused || events.length === 0) return;
    const el = scrollRef.current;
    if (!el) return;
    let raf = 0;
    const step = () => {
      if (el.scrollHeight - el.clientHeight - el.scrollTop < 1) el.scrollTop = 0;
      else el.scrollTop += 0.35;
      raf = requestAnimationFrame(step);
    };
    raf = requestAnimationFrame(step);
    return () => cancelAnimationFrame(raf);
  }, [paused, events.length]);

  return (
    <SectionCard title="Live Activity Feed" icon={Zap} live={events.length > 0} right={<button type="button" onClick={() => setPaused((p) => !p)} className="text-[8.5px] font-black uppercase tracking-wider text-white/40 hover:text-cyan-300">{paused ? 'Resume' : 'Pause'}</button>}>
      <div ref={scrollRef} onMouseEnter={() => setPaused(true)} onMouseLeave={() => setPaused(false)} className="max-h-[300px] space-y-1.5 overflow-y-auto pr-1">
        {events.length === 0 ? (
          <div className="py-8 text-center text-[10px] font-black uppercase tracking-widest text-white/30">No activity yet.</div>
        ) : events.map((ev) => {
          const t = toneClasses(ev.tone);
          return (
            <div key={ev.id} className="flex items-start gap-2 rounded-lg border border-white/5 bg-black/20 px-2.5 py-1.5">
              <span className={cn('mt-1 h-1.5 w-1.5 shrink-0 rounded-full', t.dot)} />
              <span className="w-12 shrink-0 font-mono text-[9px] text-white/35">{ev.time}</span>
              <span className="flex-1 text-[10px] font-semibold text-white/60">{ev.message}</span>
            </div>
          );
        })}
      </div>
    </SectionCard>
  );
}

/* ================================================================== */
/* 14 — Audit Trail                                                   */
/* ================================================================== */

export function AuditTrailPanel({ rows }: { rows: AuditRow[] }) {
  return (
    <SectionCard
      title="Audit Trail"
      icon={ScrollText}
      right={<button type="button" onClick={() => downloadTextFile(`qguard-migration-audit-${Date.now()}.csv`, auditToCsv(rows), 'text/csv;charset=utf-8')} className="inline-flex items-center gap-1 rounded-md border border-white/10 bg-white/5 px-2 py-1 text-[8.5px] font-black uppercase tracking-wider text-white/60 transition hover:text-cyan-300"><Download className="h-3 w-3" />CSV</button>}
    >
      <div className="overflow-x-auto">
        <table className="w-full min-w-[760px] text-left">
          <thead className="border-b border-white/10 text-[8px] font-black uppercase tracking-widest text-cyan-300/70">
            <tr>{['Timestamp', 'Actor', 'Action', 'Target', 'Outcome', 'Evidence'].map((h) => <th key={h} className="px-2 py-2">{h}</th>)}</tr>
          </thead>
          <tbody className="divide-y divide-white/5 text-[10px] font-semibold text-white/55">
            {rows.length === 0 ? (
              <tr><td colSpan={6} className="py-8 text-center text-white/30">No audit records yet.</td></tr>
            ) : rows.slice(0, 20).map((r) => {
              const t = toneClasses(r.tone);
              return (
                <tr key={r.id} className="transition hover:bg-cyan-500/[0.04]">
                  <td className="whitespace-nowrap px-2 py-2 font-mono text-[9px] text-white/50">{r.timestamp}</td>
                  <td className="px-2 py-2 font-mono text-[9px]">{r.actor}</td>
                  <td className="px-2 py-2">{r.action}</td>
                  <td className="max-w-[160px] truncate px-2 py-2 text-white/70">{r.target}</td>
                  <td className={cn('px-2 py-2 font-black uppercase', t.text)}>{r.outcome}</td>
                  <td className="px-2 py-2 text-white/45">{r.evidence}</td>
                </tr>
              );
            })}
          </tbody>
        </table>
      </div>
    </SectionCard>
  );
}

/* ================================================================== */
/* 11 — Enterprise Asset Migration Table                              */
/* ================================================================== */

const SAVED_VIEWS_KEY = 'qguard-mig-ops:asset-views:v1';
type AssetFilter = { search: string; status: MigrationStatus | 'all'; risk: string; env: string };
const DEFAULT_FILTER: AssetFilter = { search: '', status: 'all', risk: 'all', env: 'all' };
const PAGE_SIZE = 12;

export function AssetTable({ rows, onSelect }: { rows: AssetRow[]; onSelect: (id: string) => void }) {
  const [filter, setFilter] = useState<AssetFilter>(DEFAULT_FILTER);
  const [page, setPage] = useState(0);
  const [selected, setSelected] = useState<Set<string>>(new Set());
  const [sortKey, setSortKey] = useState<'risk' | 'name' | 'progress'>('risk');
  const [views, setViews] = useState<Array<{ name: string; filter: AssetFilter }>>([]);

  useEffect(() => {
    try { const raw = localStorage.getItem(SAVED_VIEWS_KEY); if (raw) setViews(JSON.parse(raw)); } catch { /* ignore */ }
  }, []);
  const persistViews = (next: Array<{ name: string; filter: AssetFilter }>) => {
    setViews(next);
    try { localStorage.setItem(SAVED_VIEWS_KEY, JSON.stringify(next)); } catch { /* ignore */ }
  };

  const environments = useMemo(() => Array.from(new Set(rows.map((r) => r.environment))).filter(Boolean), [rows]);

  const filtered = useMemo(() => {
    const q = filter.search.trim().toLowerCase();
    const out = rows.filter((r) => {
      if (filter.status !== 'all' && r.status !== filter.status) return false;
      if (filter.risk !== 'all' && r.risk.label !== filter.risk) return false;
      if (filter.env !== 'all' && r.environment !== filter.env) return false;
      if (q && !`${r.name} ${r.owner} ${r.currentCrypto} ${r.targetCrypto} ${r.type}`.toLowerCase().includes(q)) return false;
      return true;
    });
    out.sort((a, b) => sortKey === 'name' ? a.name.localeCompare(b.name) : sortKey === 'progress' ? b.progress - a.progress : b.riskScore - a.riskScore);
    return out;
  }, [rows, filter, sortKey]);

  const pageCount = Math.max(1, Math.ceil(filtered.length / PAGE_SIZE));
  const safePage = Math.min(page, pageCount - 1);
  const pageRows = filtered.slice(safePage * PAGE_SIZE, safePage * PAGE_SIZE + PAGE_SIZE);
  useEffect(() => { setPage(0); }, [filter, sortKey]);

  const toggle = (id: string) => setSelected((s) => { const n = new Set(s); n.has(id) ? n.delete(id) : n.add(id); return n; });
  const allOnPage = pageRows.length > 0 && pageRows.every((r) => selected.has(r.id));
  const toggleAll = () => setSelected((s) => { const n = new Set(s); if (allOnPage) pageRows.forEach((r) => n.delete(r.id)); else pageRows.forEach((r) => n.add(r.id)); return n; });

  const exportRows = (subset: AssetRow[]) => downloadTextFile(`qguard-migration-assets-${Date.now()}.csv`, assetsToCsv(subset), 'text/csv;charset=utf-8');

  return (
    <SectionCard
      title="Enterprise Asset Migration Table"
      icon={Database}
      right={<span className="text-[9px] font-mono uppercase tracking-widest text-white/30">{numberFmt(filtered.length)} of {numberFmt(rows.length)}</span>}
    >
      {/* Controls */}
      <div className="mb-3 flex flex-wrap items-center gap-2">
        <div className="relative">
          <Search className="pointer-events-none absolute left-2 top-1/2 h-3.5 w-3.5 -translate-y-1/2 text-white/30" />
          <input value={filter.search} onChange={(e) => setFilter((f) => ({ ...f, search: e.target.value }))} placeholder="Search assets…" className="w-48 rounded-lg border border-white/10 bg-black/30 py-1.5 pl-7 pr-2 text-[10px] text-white placeholder:text-white/25 focus:border-cyan-400/50 focus:outline-none" />
        </div>
        <FilterSelect value={filter.status} onChange={(v) => setFilter((f) => ({ ...f, status: v as MigrationStatus | 'all' }))} options={[['all', 'All Status'], ['in-progress', 'In Progress'], ['scheduled', 'Scheduled'], ['completed', 'Completed'], ['pending', 'Pending'], ['failed', 'Failed']]} />
        <FilterSelect value={filter.risk} onChange={(v) => setFilter((f) => ({ ...f, risk: v }))} options={[['all', 'All Risk'], ['Critical', 'Critical'], ['High', 'High'], ['Medium', 'Medium'], ['Low', 'Low']]} />
        <FilterSelect value={filter.env} onChange={(v) => setFilter((f) => ({ ...f, env: v }))} options={[['all', 'All Env'], ...environments.map((e) => [e, e] as [string, string])]} />
        <FilterSelect value={sortKey} onChange={(v) => setSortKey(v as typeof sortKey)} options={[['risk', 'Sort: Risk'], ['name', 'Sort: Name'], ['progress', 'Sort: Progress']]} />
        <button type="button" onClick={() => exportRows(filtered)} className="inline-flex items-center gap-1 rounded-lg border border-white/10 bg-white/5 px-2.5 py-1.5 text-[9px] font-black uppercase tracking-wider text-white/60 transition hover:text-cyan-300"><Download className="h-3 w-3" />Export</button>
        <button type="button" onClick={() => { const name = prompt('Save current view as:'); if (name) persistViews([...views.filter((v) => v.name !== name), { name, filter }]); }} className="inline-flex items-center gap-1 rounded-lg border border-white/10 bg-white/5 px-2.5 py-1.5 text-[9px] font-black uppercase tracking-wider text-white/60 transition hover:text-cyan-300"><Filter className="h-3 w-3" />Save View</button>
        {views.map((v) => (
          <button key={v.name} type="button" onClick={() => setFilter(v.filter)} className="rounded-lg border border-cyan-400/20 bg-cyan-500/5 px-2 py-1.5 text-[9px] font-bold text-cyan-300/80 transition hover:bg-cyan-500/15">{v.name}</button>
        ))}
      </div>

      {/* Bulk action bar */}
      {selected.size > 0 && (
        <div className="mb-2 flex flex-wrap items-center gap-2 rounded-lg border border-cyan-400/30 bg-cyan-500/10 px-3 py-1.5">
          <span className="text-[10px] font-black uppercase tracking-wider text-cyan-200">{selected.size} selected</span>
          <button type="button" onClick={() => exportRows(rows.filter((r) => selected.has(r.id)))} className="rounded-md border border-white/10 bg-white/5 px-2 py-0.5 text-[9px] font-bold text-white/70 hover:text-cyan-300">Export</button>
          <a href="/dashboard/migration-planner" className="rounded-md border border-white/10 bg-white/5 px-2 py-0.5 text-[9px] font-bold text-white/70 hover:text-cyan-300">Plan Migration</a>
          <button type="button" onClick={() => setSelected(new Set())} className="ml-auto text-[9px] font-bold text-white/40 hover:text-white">Clear</button>
        </div>
      )}

      <div className="overflow-x-auto">
        <table className="w-full min-w-[1100px] text-left">
          <thead className="border-b border-white/10 text-[8px] font-black uppercase tracking-widest text-cyan-300/70">
            <tr>
              <th className="px-2 py-2"><input type="checkbox" checked={allOnPage} onChange={toggleAll} className="accent-cyan-400" /></th>
              {['Asset', 'Env', 'Owner', 'Current → Target', 'Risk', 'Wave', 'CAB', 'Rollback', 'Validation', 'Status', 'Progress'].map((h) => <th key={h} className="whitespace-nowrap px-2 py-2">{h}</th>)}
            </tr>
          </thead>
          <tbody className="divide-y divide-white/5 text-[10px] font-semibold text-white/60">
            {pageRows.length === 0 ? (
              <tr><td colSpan={12} className="py-10 text-center text-[10px] font-black uppercase tracking-widest text-white/30">No assets match. Run an authorized scan to populate this inventory.</td></tr>
            ) : pageRows.map((r) => {
              const meta = STATUS_META[r.status];
              const st = toneClasses(meta.tone);
              const rt = toneClasses(r.risk.tone);
              return (
                <tr key={r.id} className="transition hover:bg-cyan-500/[0.05]">
                  <td className="px-2 py-2"><input type="checkbox" checked={selected.has(r.id)} onChange={() => toggle(r.id)} className="accent-cyan-400" /></td>
                  <td className="max-w-[150px] cursor-pointer truncate px-2 py-2 text-white/85" onClick={() => onSelect(r.id)}>{r.name}</td>
                  <td className="px-2 py-2">{r.environment}</td>
                  <td className="max-w-[110px] truncate px-2 py-2">{r.owner}</td>
                  <td className="whitespace-nowrap px-2 py-2 font-mono text-[9px] text-white/50">{r.currentCrypto} → {r.targetCrypto}</td>
                  <td className={cn('px-2 py-2 font-black', rt.text)}>{r.risk.label}</td>
                  <td className="px-2 py-2">{r.wave}</td>
                  <td className="px-2 py-2">{r.cabApproval}</td>
                  <td className="px-2 py-2 text-emerald-400/80">{r.rollback}</td>
                  <td className="px-2 py-2">{r.validation}</td>
                  <td className={cn('px-2 py-2 font-black', st.text)}>{meta.label}</td>
                  <td className="px-2 py-2">
                    <div className="flex items-center gap-1.5"><div className="h-1 w-12"><Bar value={r.progress} color={st.hex} height={4} /></div><span className="text-[9px]">{pct(r.progress)}</span></div>
                  </td>
                </tr>
              );
            })}
          </tbody>
        </table>
      </div>

      {/* Pagination */}
      {pageCount > 1 && (
        <div className="mt-3 flex items-center justify-between text-[9px] font-bold uppercase tracking-wider text-white/40">
          <span>Page {safePage + 1} of {pageCount}</span>
          <div className="flex gap-1">
            <button type="button" disabled={safePage === 0} onClick={() => setPage((p) => Math.max(0, p - 1))} className="rounded-md border border-white/10 bg-white/5 px-2 py-1 text-white/60 disabled:opacity-30">Prev</button>
            <button type="button" disabled={safePage >= pageCount - 1} onClick={() => setPage((p) => Math.min(pageCount - 1, p + 1))} className="rounded-md border border-white/10 bg-white/5 px-2 py-1 text-white/60 disabled:opacity-30">Next</button>
          </div>
        </div>
      )}
    </SectionCard>
  );
}

function FilterSelect({ value, onChange, options }: { value: string; onChange: (v: string) => void; options: Array<[string, string]> }) {
  return (
    <select value={value} onChange={(e) => onChange(e.target.value)} className="rounded-lg border border-white/10 bg-black/30 px-2 py-1.5 text-[10px] font-bold text-white/70 focus:border-cyan-400/50 focus:outline-none">
      {options.map(([v, l]) => <option key={v} value={v} className="bg-[#0b1120]">{l}</option>)}
    </select>
  );
}

/* ================================================================== */
/* Compliance mapping strip (sections 15/16 surfaced)                 */
/* ================================================================== */

export function ComplianceStrip() {
  return (
    <Panel className="p-4">
      <div className="flex flex-wrap items-center gap-2">
        <ShieldCheck className="h-4 w-4 text-cyan-300" />
        <span className="text-[10px] font-black uppercase tracking-wider text-white/70">Compliance Mapping</span>
        <span className="text-[9px] font-semibold text-white/35">Every migration is evidence-linked to:</span>
        <div className="flex flex-wrap gap-1.5">
          {COMPLIANCE_STANDARDS.map((s) => <Chip key={s} tone="info">{s}</Chip>)}
        </div>
        <a href="/dashboard/compliance" className="ml-auto inline-flex items-center gap-1 text-[9px] font-black uppercase tracking-wider text-cyan-300 hover:text-cyan-200">Evidence <ChevronRight className="h-3 w-3" /></a>
      </div>
    </Panel>
  );
}
