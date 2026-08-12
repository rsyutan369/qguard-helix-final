'use client';

import { useEffect, useMemo, useRef, useState, type ReactNode } from 'react';
import { AnimatePresence, motion, useReducedMotion } from 'framer-motion';
import {
  Activity, AlertTriangle, ArrowRight, BadgeCheck, Boxes, ChevronDown, ChevronRight,
  Download, FileWarning, Gauge, GitBranch, Info, Layers, Link2, ListChecks, Lock,
  Play, RadioTower, Route, Scale, Search, ShieldCheck, Sparkles, TrendingDown,
  TrendingUp, Unplug, Users, Workflow, type LucideIcon,
} from 'lucide-react';
import { cn } from '@/lib/utils';
import { Panel, PanelHeader, Bar, Sparkline, TONE, type Tone as PrimitiveTone } from '../_components/executive/primitives';
import type {
  AgilityAssetRow, AgilityBlocker, AgilityDistributionBucket, AgilityDomain, AgilityDrift,
  AgilityKpi, AgilityRecommendation, AgilityState, AssessmentHistoryPoint, ControlDomain,
  CouplingFinding, CryptoAgilityIntelligence, LifecycleStage, MigrationReadinessState,
  PolicyEvaluation, ReplaceabilityClass, ReplaceabilityRow, ResponsibilityRow, RuntimeCryptoEvent,
} from '@/lib/crypto-agility/agility-intelligence';
import { AGILITY_STATE_DEFINITION, CONTROL_DOMAIN_LABEL } from '@/lib/crypto-agility/agility-intelligence';
import {
  AGILITY_STATE_LABEL, CONTROL_DOMAIN_TONE, MIGRATION_READINESS_LABEL, READINESS_TONE,
  REPLACEABILITY_GLYPH, REPLACEABILITY_LABEL, REPLACEABILITY_TONE, SEVERITY_TONE,
  STATE_GLYPH, STATE_HEX, STATE_TONE, TONE_HEX, absoluteTime, confidenceLabel, domainTone,
  numberFmt, pctFmt, relativeTime, scoreFmt, type AgilityFilters, type AssetSortKey, type Tone,
} from './_agility-lib';

/* ================================================================== */
/* Shared primitives                                                   */
/* ================================================================== */

export function SectionCard({
  id, title, icon, right, children, live, className,
}: {
  id?: string; title: string; icon?: LucideIcon; right?: ReactNode;
  children: ReactNode; live?: boolean; className?: string;
}) {
  return (
    <Panel className={cn('p-5', className)}>
      {id && <div id={id} className="scroll-mt-24" />}
      <PanelHeader title={title} icon={icon} right={right} live={live} />
      {children}
    </Panel>
  );
}

export function Chip({ children, tone = 'neutral', title, glyph }: { children: ReactNode; tone?: Tone; title?: string; glyph?: string }) {
  const t = TONE[tone as PrimitiveTone];
  return (
    <span title={title} className={cn('inline-flex items-center gap-1 rounded-md border px-2 py-0.5 text-[9px] font-black uppercase tracking-wider', t.text, t.soft, t.border)}>
      {glyph && <span aria-hidden="true">{glyph}</span>}
      {children}
    </span>
  );
}

export function StateChip({ state }: { state: AgilityState }) {
  return (
    <Chip tone={STATE_TONE[state]} glyph={STATE_GLYPH[state]} title={AGILITY_STATE_DEFINITION[state]}>
      {AGILITY_STATE_LABEL[state]}
    </Chip>
  );
}

export function ReplaceabilityChip({ value }: { value: ReplaceabilityClass }) {
  return (
    <Chip tone={REPLACEABILITY_TONE[value]} glyph={REPLACEABILITY_GLYPH[value]} title={REPLACEABILITY_LABEL[value]}>
      {REPLACEABILITY_LABEL[value]}
    </Chip>
  );
}

/** Count-up that respects prefers-reduced-motion and only runs on real change. */
export function AnimatedNumber({ value, className, fallback = 'Unknown' }: { value: number | null; className?: string; fallback?: string }) {
  const reduce = useReducedMotion();
  const [display, setDisplay] = useState(value ?? 0);
  const fromRef = useRef(value ?? 0);

  useEffect(() => {
    if (value === null) return;
    const from = fromRef.current;
    if (reduce || from === value) { fromRef.current = value; setDisplay(value); return; }
    let raf = 0;
    const start = performance.now();
    const tick = (now: number) => {
      const p = Math.min(1, (now - start) / 600);
      const eased = 1 - Math.pow(1 - p, 3);
      setDisplay(from + (value - from) * eased);
      if (p < 1) raf = requestAnimationFrame(tick);
      else { fromRef.current = value; setDisplay(value); }
    };
    raf = requestAnimationFrame(tick);
    return () => cancelAnimationFrame(raf);
  }, [value, reduce]);

  if (value === null) return <span className={className}>{fallback}</span>;
  return <span className={className}>{Math.round(display)}</span>;
}

function EmptyBlock({ icon: Icon, title, detail, cta }: { icon: LucideIcon; title: string; detail: string; cta?: { label: string; href: string } }) {
  return (
    <div className="flex min-h-[150px] flex-col items-center justify-center gap-2 rounded-lg border border-dashed border-white/12 bg-white/[0.02] p-6 text-center">
      <Icon className="h-6 w-6 text-white/25" />
      <p className="text-[12px] font-bold text-white/60">{title}</p>
      <p className="max-w-lg text-[11px] leading-relaxed text-white/35">{detail}</p>
      {cta && (
        <a href={cta.href} className="mt-1 rounded border border-cyan-400/40 bg-cyan-500/10 px-3 py-1.5 text-[10px] font-black uppercase tracking-wider text-cyan-200 no-underline transition hover:bg-cyan-500/20">
          {cta.label}
        </a>
      )}
    </div>
  );
}

/* ================================================================== */
/* 1 — Hero: score, readiness, KPIs                                    */
/* ================================================================== */

export function AgilityHero({
  intel, onExplain, onFilterState,
}: {
  intel: CryptoAgilityIntelligence;
  onExplain: () => void;
  onFilterState: (state: AgilityState) => void;
}) {
  const score = intel.score.agilityScore;
  const tone: Tone = score === null ? 'info' : score >= 70 ? 'good' : score >= 50 ? 'warning' : 'critical';
  const hex = TONE_HEX[tone];
  const circumference = 2 * Math.PI * 52;
  const reduce = useReducedMotion();

  return (
    <Panel className="relative overflow-hidden p-5">
      <div className="pointer-events-none absolute inset-0 bg-[radial-gradient(120%_120%_at_0%_0%,rgba(34,211,238,0.10),transparent_58%)]" />
      <div className="relative grid gap-6 lg:grid-cols-[auto_minmax(0,1fr)]">
        {/* Score dial */}
        <div className="flex items-center gap-5">
          <div className="relative grid h-[132px] w-[132px] place-items-center">
            <svg viewBox="0 0 120 120" className="h-[132px] w-[132px] -rotate-90" aria-hidden="true">
              <circle cx="60" cy="60" r="52" fill="none" stroke="rgba(255,255,255,0.07)" strokeWidth="8" />
              <motion.circle
                cx="60" cy="60" r="52" fill="none" stroke={hex} strokeWidth="8" strokeLinecap="round"
                strokeDasharray={circumference}
                initial={reduce ? false : { strokeDashoffset: circumference }}
                animate={{ strokeDashoffset: circumference - ((score ?? 0) / 100) * circumference }}
                transition={{ duration: reduce ? 0 : 1, ease: 'easeOut' }}
              />
            </svg>
            <div className="absolute flex flex-col items-center leading-none">
              <AnimatedNumber value={score} className="text-[38px] font-black text-white" fallback="—" />
              <span className="mt-0.5 text-[9px] font-black uppercase tracking-[0.18em] text-white/35">/ 100</span>
            </div>
          </div>
          <div className="min-w-0">
            <div className="text-[9px] font-black uppercase tracking-[0.2em] text-white/40">Crypto Agility Score</div>
            <div className="mt-1 text-2xl font-black leading-none" style={{ color: hex }}>{intel.score.agilityLevel}</div>
            <div className="mt-2 flex flex-wrap items-center gap-1.5">
              <Chip tone={tone}>{confidenceLabel(intel.confidence)}</Chip>
              <Chip tone="info">{intel.score.scoredWeight}% of model measured</Chip>
              {intel.score.blockerPenalty > 0 && <Chip tone="critical">−{intel.score.blockerPenalty} blocker penalty</Chip>}
            </div>
            <button
              type="button"
              onClick={onExplain}
              className="mt-2.5 inline-flex items-center gap-1.5 rounded-lg border border-cyan-400/30 bg-cyan-500/10 px-2.5 py-1.5 text-[9px] font-black uppercase tracking-wider text-cyan-200 transition hover:bg-cyan-500/20"
            >
              <Info className="h-3 w-3" /> How is this score calculated?
            </button>
          </div>
        </div>

        {/* Secondary metrics + distribution filter chips */}
        <div className="space-y-3">
          <div className="grid grid-cols-2 gap-3 sm:grid-cols-4">
            <HeroStat label="Migration Readiness" value={pctFmt(intel.score.migrationReadinessPct)} detail={`${intel.readiness.ready} ready · ${intel.readiness.blocked} blocked`} tone={intel.score.migrationReadinessPct === null ? 'info' : intel.score.migrationReadinessPct >= 70 ? 'good' : intel.score.migrationReadinessPct >= 40 ? 'warning' : 'critical'} />
            <HeroStat label="Assets Evaluated" value={numberFmt(intel.score.assetsEvaluated)} detail={`of ${numberFmt(intel.evidence.assets)} discovered`} tone="neutral" />
            <HeroStat label="Critical Blockers" value={numberFmt(intel.score.criticalBlockers)} detail={`${intel.blockers.length} blocker group(s)`} tone={intel.score.criticalBlockers > 0 ? 'critical' : 'good'} />
            <HeroStat label="Last Assessment" value={relativeTime(intel.lastAssessmentAt)} detail={absoluteTime(intel.lastAssessmentAt)} tone="info" />
          </div>

          <div className="flex flex-wrap items-center gap-2 border-t border-white/8 pt-3">
            <span className="text-[9px] font-black uppercase tracking-widest text-white/30">Agility state</span>
            {intel.distribution.map((bucket) => (
              <button
                key={bucket.state}
                type="button"
                onClick={() => onFilterState(bucket.state)}
                title={`${bucket.definition} — click to filter the asset table`}
                className={cn(
                  'inline-flex items-center gap-1.5 rounded-lg border px-2.5 py-1.5 text-[9px] font-black uppercase tracking-wider transition hover:-translate-y-px',
                  TONE[STATE_TONE[bucket.state] as PrimitiveTone].border,
                  TONE[STATE_TONE[bucket.state] as PrimitiveTone].soft,
                  TONE[STATE_TONE[bucket.state] as PrimitiveTone].text,
                )}
              >
                <span aria-hidden="true">{STATE_GLYPH[bucket.state]}</span>
                {AGILITY_STATE_LABEL[bucket.state]}
                <span className="rounded bg-black/30 px-1 font-mono text-[9px] text-white/70">{numberFmt(bucket.count)}</span>
              </button>
            ))}
          </div>
        </div>
      </div>
    </Panel>
  );
}

function HeroStat({ label, value, detail, tone }: { label: string; value: string; detail: string; tone: Tone }) {
  const t = TONE[tone as PrimitiveTone];
  return (
    <div className={cn('rounded-lg border bg-white/[0.02] px-3 py-2.5', t.border)}>
      <div className="text-[8px] font-black uppercase leading-tight tracking-wider text-white/40">{label}</div>
      <div className={cn('mt-1 truncate text-[17px] font-black leading-none', t.text)}>{value}</div>
      <div className="mt-1 truncate text-[9px] font-semibold text-white/35" title={detail}>{detail}</div>
    </div>
  );
}

/* ================================================================== */
/* 2 — Executive KPI strip                                             */
/* ================================================================== */

export function AgilityKpiStrip({ kpis, onDrill }: { kpis: AgilityKpi[]; onDrill: (kpi: AgilityKpi) => void }) {
  return (
    <div className="grid grid-cols-2 gap-2.5 sm:grid-cols-3 lg:grid-cols-4 xl:grid-cols-7">
      {kpis.map((kpi) => {
        const t = TONE[kpi.tone as PrimitiveTone];
        return (
          <button key={kpi.key} type="button" onClick={() => onDrill(kpi)} title={kpi.basis} className="group/kpi text-left">
            <Panel className="h-full p-3 transition-transform group-hover/kpi:-translate-y-0.5">
              <div className="truncate text-[8px] font-black uppercase tracking-wider text-white/45">{kpi.label}</div>
              <div className={cn('mt-1.5 truncate text-lg font-black leading-none', t.text)}>{kpi.value}</div>
              <div className="mt-1 truncate text-[8.5px] font-semibold text-white/35">{kpi.detail}</div>
            </Panel>
          </button>
        );
      })}
    </div>
  );
}

/* ================================================================== */
/* 3 — Agility posture (11 domains)                                    */
/* ================================================================== */

export function AgilityPosture({ domains, onSelect }: { domains: AgilityDomain[]; onSelect: (domain: AgilityDomain) => void }) {
  const measured = domains.filter((d) => d.score !== null).length;
  return (
    <SectionCard
      id="agility-posture"
      title="Crypto Agility Posture"
      icon={Gauge}
      right={<span className="font-mono text-[9px] uppercase tracking-widest text-white/30">{measured}/{domains.length} domains measured</span>}
    >
      <div className="space-y-1.5">
        {domains.map((domain) => {
          const tone = domainTone(domain);
          const hex = TONE_HEX[tone];
          return (
            <button
              key={domain.key}
              type="button"
              onClick={() => onSelect(domain)}
              className="group grid w-full grid-cols-[minmax(0,1.15fr)_minmax(0,1fr)_auto] items-center gap-3 rounded-lg border border-white/6 bg-white/[0.015] px-3 py-2.5 text-left transition hover:border-cyan-400/30 hover:bg-cyan-500/[0.05]"
            >
              <div className="min-w-0">
                <div className="flex items-center gap-2">
                  <span className="truncate text-[11.5px] font-black text-white/85">{domain.label}</span>
                  <Chip tone={STATE_TONE[domain.state]} glyph={STATE_GLYPH[domain.state]}>{AGILITY_STATE_LABEL[domain.state]}</Chip>
                </div>
                <div className="mt-0.5 truncate text-[9.5px] text-white/35" title={domain.question}>{domain.question}</div>
              </div>

              <div className="min-w-0">
                {domain.score === null ? (
                  <div className="flex items-center gap-2">
                    <span className="rounded border border-white/10 bg-white/5 px-2 py-1 text-[9px] font-black uppercase tracking-wider text-white/45">Insufficient Evidence</span>
                    <span className="truncate text-[9px] text-white/25">excluded from the score</span>
                  </div>
                ) : (
                  <>
                    <Bar value={domain.score} color={hex} height={7} />
                    <div className="mt-1 flex items-center gap-2 text-[9px] text-white/35">
                      <span>Coverage {domain.evidenceCoverage}%</span>
                      <span>·</span>
                      <span>{confidenceLabel(domain.confidence)}</span>
                      {domain.blockers > 0 && <><span>·</span><span className="text-amber-300">{domain.blockers} blocker(s)</span></>}
                    </div>
                  </>
                )}
              </div>

              <div className="flex items-center gap-3">
                <div className="text-right">
                  <div className="font-mono text-base font-black leading-none" style={{ color: domain.score === null ? 'rgba(255,255,255,0.35)' : hex }}>
                    {domain.score === null ? '—' : domain.score}
                  </div>
                  <div className="mt-0.5 text-[8px] font-bold uppercase tracking-wider text-white/25">weight {domain.weight}</div>
                </div>
                <ChevronRight className="h-4 w-4 text-white/20 transition group-hover:translate-x-0.5 group-hover:text-cyan-300" />
              </div>
            </button>
          );
        })}
      </div>
      <p className="mt-3 border-t border-white/8 pt-2.5 text-[10px] leading-relaxed text-white/35">
        Domains with no supporting evidence are excluded and their weight renormalised — they are never scored as zero. <span className="text-white/55">Unknown does not mean safe.</span>
      </p>
    </SectionCard>
  );
}

/* ================================================================== */
/* 4 — Agility distribution                                            */
/* ================================================================== */

export function AgilityDistribution({
  buckets, active, onSelect,
}: {
  buckets: AgilityDistributionBucket[]; active: AgilityState | 'all'; onSelect: (state: AgilityState) => void;
}) {
  const total = buckets.reduce((sum, b) => sum + b.count, 0);
  return (
    <SectionCard id="agility-distribution" title="Agility State Distribution" icon={Layers} right={<span className="font-mono text-[9px] uppercase tracking-widest text-white/30">{numberFmt(total)} assets</span>}>
      {total === 0 ? (
        <EmptyBlock icon={Layers} title="No assets classified yet" detail="Agility state is derived from cryptographic evidence bound to each asset." cta={{ label: 'Run Discovery Scan', href: '/dashboard/scanner' }} />
      ) : (
        <div className="space-y-2">
          {buckets.map((bucket) => {
            const isActive = active === bucket.state;
            return (
              <button
                key={bucket.state}
                type="button"
                onClick={() => onSelect(bucket.state)}
                aria-pressed={isActive}
                title={bucket.definition}
                className={cn(
                  'grid w-full grid-cols-[130px_minmax(0,1fr)_58px] items-center gap-3 rounded-lg border px-3 py-2 text-left transition',
                  isActive ? 'border-cyan-400/50 bg-cyan-500/10' : 'border-white/6 bg-white/[0.015] hover:border-white/15',
                )}
              >
                <span className="flex items-center gap-1.5 text-[10.5px] font-black uppercase tracking-wider" style={{ color: STATE_HEX[bucket.state] }}>
                  <span aria-hidden="true">{STATE_GLYPH[bucket.state]}</span>
                  {bucket.label}
                </span>
                <span className="h-2.5 overflow-hidden rounded-full bg-white/8">
                  <span className="block h-full rounded-full transition-all duration-700" style={{ width: `${bucket.share}%`, backgroundColor: STATE_HEX[bucket.state] }} />
                </span>
                <span className="text-right font-mono text-[12px] font-black text-white/85">{numberFmt(bucket.count)}</span>
              </button>
            );
          })}
          <p className="pt-1 text-[10px] leading-relaxed text-white/35">Selecting a state filters the asset workspace, coupling analysis and responsibility matrix below.</p>
        </div>
      )}
    </SectionCard>
  );
}

/* ================================================================== */
/* 5 — Coupling analysis                                               */
/* ================================================================== */

export function CouplingAnalysis({ findings, onSelect }: { findings: CouplingFinding[]; onSelect: (finding: CouplingFinding) => void }) {
  const [expanded, setExpanded] = useState(false);
  const visible = expanded ? findings.slice(0, 60) : findings.slice(0, 8);

  return (
    <SectionCard
      id="coupling-analysis"
      title="Crypto Coupling Analysis"
      icon={Unplug}
      right={<Chip tone={findings.length ? 'warning' : 'good'}>{numberFmt(findings.length)} finding(s)</Chip>}
    >
      {findings.length === 0 ? (
        <EmptyBlock
          icon={Unplug}
          title="No cryptographic coupling detected"
          detail="No hard-coded algorithm, embedded certificate, static trust anchor, legacy provider or vendor-locked cryptography was found in the evidence available. Coupling is only detectable where source, certificate or provider evidence exists — extend scan coverage to raise confidence."
          cta={{ label: 'Extend Scan Coverage', href: '/dashboard/scanner' }}
        />
      ) : (
        <>
          <div className="space-y-1.5">
            {visible.map((finding) => (
              <button
                key={finding.id}
                type="button"
                onClick={() => onSelect(finding)}
                className="group grid w-full grid-cols-[auto_minmax(0,1fr)_auto] items-start gap-3 rounded-lg border border-white/6 bg-white/[0.015] p-2.5 text-left transition hover:border-cyan-400/30 hover:bg-cyan-500/[0.05]"
              >
                <span className={cn('mt-0.5 grid h-6 w-6 shrink-0 place-items-center rounded border', TONE[SEVERITY_TONE[finding.severity] as PrimitiveTone].border, TONE[SEVERITY_TONE[finding.severity] as PrimitiveTone].soft)}>
                  <FileWarning className={cn('h-3 w-3', TONE[SEVERITY_TONE[finding.severity] as PrimitiveTone].text)} />
                </span>
                <div className="min-w-0">
                  <div className="flex flex-wrap items-center gap-1.5">
                    <span className="truncate text-[11.5px] font-black text-white/85">{finding.title}</span>
                    <Chip tone={SEVERITY_TONE[finding.severity]}>{finding.severity}</Chip>
                    <Chip tone={CONTROL_DOMAIN_TONE[finding.controlDomain]}>{CONTROL_DOMAIN_LABEL[finding.controlDomain]}</Chip>
                  </div>
                  <div className="mt-1 flex flex-wrap items-center gap-x-3 gap-y-0.5 text-[9.5px] text-white/40">
                    <span className="truncate">{finding.asset}</span>
                    <span>·</span>
                    <span>{finding.dependencyCount} dependency(ies)</span>
                    <span>·</span>
                    <span>{finding.agilityImpactLabel}</span>
                    <span>·</span>
                    <span className="truncate text-white/30">{finding.evidenceSource}</span>
                  </div>
                  <div className="mt-1 truncate font-mono text-[9.5px] text-cyan-300/60" title={finding.evidence}>{finding.evidence}</div>
                </div>
                <div className="flex shrink-0 items-center gap-2">
                  <div className="hidden w-20 sm:block">
                    <Bar value={finding.agilityImpact} color={TONE_HEX[SEVERITY_TONE[finding.severity]]} height={5} />
                    <div className="mt-0.5 text-right text-[8px] font-bold uppercase tracking-wider text-white/25">impact {finding.agilityImpact}</div>
                  </div>
                  <ChevronRight className="h-4 w-4 text-white/20 transition group-hover:translate-x-0.5 group-hover:text-cyan-300" />
                </div>
              </button>
            ))}
          </div>
          {findings.length > 8 && (
            <button type="button" onClick={() => setExpanded((v) => !v)} className="mt-2 inline-flex items-center gap-1.5 text-[10px] font-black uppercase tracking-wider text-cyan-300 hover:text-cyan-200">
              <ChevronDown className={cn('h-3.5 w-3.5 transition-transform', expanded && 'rotate-180')} />
              {expanded ? 'Show less' : `Show all ${Math.min(60, findings.length)} findings`}
            </button>
          )}
        </>
      )}
    </SectionCard>
  );
}

/* ================================================================== */
/* 6 — Replaceability matrix                                           */
/* ================================================================== */

export function ReplaceabilityMatrix({
  rows, onSelect, onExport,
}: {
  rows: ReplaceabilityRow[]; onSelect: (row: ReplaceabilityRow) => void; onExport: () => void;
}) {
  const [query, setQuery] = useState('');
  const [page, setPage] = useState(0);
  const pageSize = 12;

  const filtered = useMemo(() => {
    const q = query.trim().toLowerCase();
    if (!q) return rows;
    return rows.filter((r) => `${r.currentAlgorithm} ${r.proposedReplacement} ${r.standard} ${r.replaceabilityLabel}`.toLowerCase().includes(q));
  }, [rows, query]);

  const pages = Math.max(1, Math.ceil(filtered.length / pageSize));
  const current = Math.min(page, pages - 1);
  const visible = filtered.slice(current * pageSize, current * pageSize + pageSize);

  return (
    <SectionCard
      id="replaceability"
      title="Algorithm Replaceability Matrix"
      icon={Scale}
      right={
        <div className="flex items-center gap-2">
          <label className="relative hidden sm:block">
            <span className="sr-only">Filter algorithms</span>
            <Search className="pointer-events-none absolute left-2 top-1/2 h-3 w-3 -translate-y-1/2 text-white/30" />
            <input
              value={query}
              onChange={(e) => { setQuery(e.target.value); setPage(0); }}
              placeholder="Filter algorithms…"
              className="h-7 w-40 rounded border border-white/10 bg-black/30 pl-7 pr-2 text-[10px] text-white/80 placeholder:text-white/25 focus:border-cyan-400/50 focus:outline-none"
            />
          </label>
          <button type="button" onClick={onExport} title="Export matrix as CSV" className="inline-flex items-center gap-1 rounded border border-white/10 bg-white/5 px-2 py-1 text-[9px] font-black uppercase tracking-wider text-white/55 transition hover:text-cyan-300">
            <Download className="h-3 w-3" /> CSV
          </button>
        </div>
      }
    >
      {rows.length === 0 ? (
        <EmptyBlock icon={Scale} title="No algorithms resolved" detail="The replaceability matrix maps every observed primitive to its NIST-approved replacement. It populates once cryptographic evidence exists." cta={{ label: 'Run Discovery Scan', href: '/dashboard/scanner' }} />
      ) : (
        <>
          <div className="overflow-x-auto">
            <table className="w-full min-w-[960px] border-collapse text-left">
              <caption className="sr-only">Algorithm replaceability: current algorithm, proposed NIST replacement, affected assets, replaceability verdict, dependencies, complexity, compatibility, risk and status.</caption>
              <thead>
                <tr className="border-b border-white/10">
                  {['Current Algorithm', 'Proposed Replacement', 'Assets', 'Replaceability', 'Deps', 'Complexity', 'Compatibility', 'Risk', 'Status'].map((h) => (
                    <th key={h} scope="col" className="px-2.5 py-2 text-[8.5px] font-black uppercase tracking-[0.14em] text-cyan-300/70">{h}</th>
                  ))}
                </tr>
              </thead>
              <tbody className="divide-y divide-white/5">
                {visible.map((row) => (
                  <tr key={row.id} className="cursor-pointer transition hover:bg-cyan-500/[0.05]" onClick={() => onSelect(row)}>
                    <td className="px-2.5 py-2">
                      <div className="font-mono text-[11px] font-black text-white/90">{row.currentAlgorithm}</div>
                      <div className="mt-0.5 text-[8.5px] uppercase tracking-wider text-white/30">{row.classification}</div>
                    </td>
                    <td className="px-2.5 py-2">
                      <div className="font-mono text-[10.5px] font-bold text-cyan-300">{row.proposedReplacement}</div>
                      <div className="mt-0.5 text-[8.5px] text-white/30">{row.standard}</div>
                    </td>
                    <td className="px-2.5 py-2">
                      <div className="font-mono text-[11px] font-bold text-white/75">{numberFmt(row.assets)}</div>
                      <div className="text-[8.5px] text-white/30">{numberFmt(row.instances)} inst.</div>
                    </td>
                    <td className="px-2.5 py-2"><ReplaceabilityChip value={row.replaceability} /></td>
                    <td className="px-2.5 py-2 font-mono text-[11px] text-white/60">{numberFmt(row.dependencies)}</td>
                    <td className="px-2.5 py-2">
                      <Chip tone={row.migrationComplexity === 'Low' ? 'good' : row.migrationComplexity === 'Medium' ? 'warning' : row.migrationComplexity === 'High' ? 'critical' : 'info'}>{row.migrationComplexity}</Chip>
                    </td>
                    <td className="px-2.5 py-2">
                      <div className="max-w-[190px] truncate text-[10px] text-white/55" title={row.compatibility}>{row.compatibility}</div>
                      {row.compatibilityScore !== null && <div className="mt-1 w-20"><Bar value={row.compatibilityScore} color={row.compatibilityScore >= 75 ? TONE_HEX.good : row.compatibilityScore >= 50 ? TONE_HEX.warning : TONE_HEX.critical} height={4} /></div>}
                    </td>
                    <td className="px-2.5 py-2"><Chip tone={SEVERITY_TONE[row.risk]}>{row.risk}</Chip></td>
                    <td className="px-2.5 py-2"><StateChip state={row.status} /></td>
                  </tr>
                ))}
              </tbody>
            </table>
          </div>

          <div className="mt-3 flex flex-wrap items-center justify-between gap-2 border-t border-white/8 pt-2.5">
            <div className="flex flex-wrap items-center gap-2 text-[9px] font-bold uppercase tracking-wider text-white/35">
              <span>Replaceability test:</span>
              {(['configuration', 'library', 'code', 'architecture', 'vendor'] as ReplaceabilityClass[]).map((c) => (
                <span key={c} className="inline-flex items-center gap-1">
                  <span aria-hidden="true">{REPLACEABILITY_GLYPH[c]}</span>{REPLACEABILITY_LABEL[c]}
                </span>
              ))}
            </div>
            {pages > 1 && (
              <div className="flex items-center gap-2">
                <button type="button" disabled={current === 0} onClick={() => setPage(current - 1)} className="rounded border border-white/10 px-2 py-1 text-[9px] font-black uppercase text-white/55 disabled:opacity-30">Prev</button>
                <span className="font-mono text-[9px] text-white/40">{current + 1} / {pages}</span>
                <button type="button" disabled={current >= pages - 1} onClick={() => setPage(current + 1)} className="rounded border border-white/10 px-2 py-1 text-[9px] font-black uppercase text-white/55 disabled:opacity-30">Next</button>
              </div>
            )}
          </div>
        </>
      )}
    </SectionCard>
  );
}

/* ================================================================== */
/* 7 — Asset workspace (migration readiness)                           */
/* ================================================================== */

export function AgilityAssetWorkspace({
  rows, total, filters, sort, direction, onSort, onSelect, onExport, onClearFilters,
}: {
  rows: AgilityAssetRow[];
  total: number;
  filters: AgilityFilters;
  sort: AssetSortKey;
  direction: 'asc' | 'desc';
  onSort: (key: AssetSortKey) => void;
  onSelect: (row: AgilityAssetRow) => void;
  onExport: () => void;
  onClearFilters: () => void;
}) {
  const [page, setPage] = useState(0);
  const pageSize = 15;
  useEffect(() => { setPage(0); }, [filters, sort, direction]);

  const pages = Math.max(1, Math.ceil(rows.length / pageSize));
  const current = Math.min(page, pages - 1);
  const visible = rows.slice(current * pageSize, current * pageSize + pageSize);

  const header = (key: AssetSortKey, label: string) => (
    <th scope="col" className="px-2.5 py-2 text-[8.5px] font-black uppercase tracking-[0.14em] text-cyan-300/70">
      <button type="button" onClick={() => onSort(key)} className="inline-flex items-center gap-1 hover:text-cyan-200">
        {label}
        {sort === key && <span aria-hidden="true">{direction === 'asc' ? '▲' : '▼'}</span>}
      </button>
    </th>
  );

  return (
    <SectionCard
      id="agility-assets"
      title="Asset Agility & Migration Readiness"
      icon={Boxes}
      right={
        <div className="flex items-center gap-2">
          <span className="font-mono text-[9px] uppercase tracking-widest text-white/30">{numberFmt(rows.length)} / {numberFmt(total)}</span>
          <button type="button" onClick={onExport} title="Export the filtered rows as CSV" className="inline-flex items-center gap-1 rounded border border-white/10 bg-white/5 px-2 py-1 text-[9px] font-black uppercase tracking-wider text-white/55 transition hover:text-cyan-300">
            <Download className="h-3 w-3" /> CSV
          </button>
        </div>
      }
    >
      {total === 0 ? (
        <EmptyBlock icon={Boxes} title="No assets discovered" detail="Crypto agility is evaluated per asset. Run a discovery scan to build the inventory this workspace operates on." cta={{ label: 'Run Discovery Scan', href: '/dashboard/scanner' }} />
      ) : rows.length === 0 ? (
        <div className="flex min-h-[140px] flex-col items-center justify-center gap-2 rounded-lg border border-dashed border-white/12 bg-white/[0.02] p-6 text-center">
          <Search className="h-6 w-6 text-white/25" />
          <p className="text-[12px] font-bold text-white/60">No assets match the current filters</p>
          <button type="button" onClick={onClearFilters} className="rounded border border-cyan-400/40 bg-cyan-500/10 px-3 py-1.5 text-[10px] font-black uppercase tracking-wider text-cyan-200">Clear filters</button>
        </div>
      ) : (
        <>
          <div className="overflow-x-auto">
            <table className="w-full min-w-[1040px] border-collapse text-left">
              <caption className="sr-only">Assets with their agility state, replaceability verdict, migration readiness, current and target cryptography, dependency count, blockers and next action.</caption>
              <thead>
                <tr className="border-b border-white/10">
                  {header('name', 'Asset')}
                  <th scope="col" className="px-2.5 py-2 text-[8.5px] font-black uppercase tracking-[0.14em] text-cyan-300/70">Agility</th>
                  <th scope="col" className="px-2.5 py-2 text-[8.5px] font-black uppercase tracking-[0.14em] text-cyan-300/70">Replaceability</th>
                  <th scope="col" className="px-2.5 py-2 text-[8.5px] font-black uppercase tracking-[0.14em] text-cyan-300/70">Current → Target</th>
                  <th scope="col" className="px-2.5 py-2 text-[8.5px] font-black uppercase tracking-[0.14em] text-cyan-300/70">Readiness</th>
                  {header('dependencies', 'Deps')}
                  {header('blockers', 'Blockers')}
                  <th scope="col" className="px-2.5 py-2 text-[8.5px] font-black uppercase tracking-[0.14em] text-cyan-300/70">Owner</th>
                  {header('risk', 'Risk')}
                  <th scope="col" className="px-2.5 py-2 text-[8.5px] font-black uppercase tracking-[0.14em] text-cyan-300/70">Next</th>
                </tr>
              </thead>
              <tbody className="divide-y divide-white/5">
                {visible.map((row) => (
                  <tr key={row.id} className="cursor-pointer transition hover:bg-cyan-500/[0.05]" onClick={() => onSelect(row)}>
                    <td className="px-2.5 py-2">
                      <div className="max-w-[210px] truncate text-[11.5px] font-black text-white/90" title={row.name}>{row.name}</div>
                      <div className="mt-0.5 truncate text-[8.5px] uppercase tracking-wider text-white/30">{row.type} · {row.environment}{row.internetFacing ? ' · internet-facing' : ''}</div>
                    </td>
                    <td className="px-2.5 py-2">
                      <StateChip state={row.agilityState} />
                      {row.agilityScore !== null && <div className="mt-1 font-mono text-[9px] text-white/40">{row.agilityScore}/100</div>}
                      {row.hasEvidence && !row.couplingAssessed && (
                        <div
                          className="mt-1 inline-flex items-center gap-1 text-[8px] font-black uppercase tracking-wider text-amber-300/80"
                          title="Only transport/certificate evidence exists for this asset — application-level coupling was never assessed, so it cannot be confirmed configuration-replaceable."
                        >
                          <AlertTriangle className="h-2.5 w-2.5" /> Edge-only
                        </div>
                      )}
                    </td>
                    <td className="px-2.5 py-2"><ReplaceabilityChip value={row.replaceability} /></td>
                    <td className="px-2.5 py-2">
                      <div className="max-w-[190px] truncate font-mono text-[10px] text-white/60" title={row.currentAlgorithms.join(', ')}>{row.currentAlgorithms.join(', ') || '—'}</div>
                      <div className="max-w-[190px] truncate font-mono text-[10px] text-cyan-300/80" title={row.targetAlgorithms.join(', ')}>{row.targetAlgorithms.length ? `→ ${row.targetAlgorithms[0]}` : '—'}</div>
                    </td>
                    <td className="px-2.5 py-2"><Chip tone={READINESS_TONE[row.readiness]}>{MIGRATION_READINESS_LABEL[row.readiness]}</Chip></td>
                    <td className="px-2.5 py-2 font-mono text-[11px] text-white/60">{numberFmt(row.dependencies)}</td>
                    <td className="px-2.5 py-2 font-mono text-[11px]" style={{ color: row.blockers ? TONE_HEX.critical : 'rgba(255,255,255,0.4)' }}>{numberFmt(row.blockers)}</td>
                    <td className="px-2.5 py-2">
                      <div className="max-w-[130px] truncate text-[10px] text-white/55" title={row.owner}>{row.owner}</div>
                      <Chip tone={CONTROL_DOMAIN_TONE[row.controlDomain]}>{row.controlDomain}</Chip>
                    </td>
                    <td className="px-2.5 py-2 font-mono text-[11px] font-bold text-white/70">{row.riskScore}</td>
                    <td className="px-2.5 py-2">
                      <span className="inline-flex items-center gap-1 rounded border border-cyan-400/25 bg-cyan-500/10 px-2 py-1 text-[8.5px] font-black uppercase tracking-wider text-cyan-200">
                        {row.nextAction} <ArrowRight className="h-2.5 w-2.5" />
                      </span>
                    </td>
                  </tr>
                ))}
              </tbody>
            </table>
          </div>

          {pages > 1 && (
            <div className="mt-3 flex items-center justify-end gap-2 border-t border-white/8 pt-2.5">
              <button type="button" disabled={current === 0} onClick={() => setPage(current - 1)} className="rounded border border-white/10 px-2.5 py-1 text-[9px] font-black uppercase text-white/55 disabled:opacity-30">Prev</button>
              <span className="font-mono text-[9px] text-white/40">Page {current + 1} of {pages}</span>
              <button type="button" disabled={current >= pages - 1} onClick={() => setPage(current + 1)} className="rounded border border-white/10 px-2.5 py-1 text-[9px] font-black uppercase text-white/55 disabled:opacity-30">Next</button>
            </div>
          )}
        </>
      )}
    </SectionCard>
  );
}

/* ================================================================== */
/* 8 — Blockers                                                        */
/* ================================================================== */

export function AgilityBlockers({ blockers, onSelect }: { blockers: AgilityBlocker[]; onSelect: (blocker: AgilityBlocker) => void }) {
  return (
    <SectionCard
      id="agility-blockers"
      title="Agility Blockers"
      icon={AlertTriangle}
      right={<Chip tone={blockers.length ? 'critical' : 'good'}>{numberFmt(blockers.reduce((s, b) => s + b.count, 0))} across {blockers.length} category(ies)</Chip>}
    >
      {blockers.length === 0 ? (
        <EmptyBlock icon={ShieldCheck} title="No agility blockers detected" detail="Nothing in the available evidence prevents a cryptographic change today. Keep discovery coverage current so newly introduced coupling is caught." cta={{ label: 'Review Scan Coverage', href: '/dashboard/scanner' }} />
      ) : (
        <div className="grid gap-2.5 md:grid-cols-2">
          {blockers.map((blocker) => {
            const tone = SEVERITY_TONE[blocker.severity];
            const t = TONE[tone as PrimitiveTone];
            return (
              <button key={blocker.id} type="button" onClick={() => onSelect(blocker)} className={cn('group rounded-lg border bg-white/[0.015] p-3 text-left transition hover:-translate-y-px', t.border)}>
                <div className="flex items-start justify-between gap-2">
                  <div className="min-w-0">
                    <div className="flex flex-wrap items-center gap-1.5">
                      <span className={cn('text-[10px] font-black uppercase tracking-wider', t.text)}>{blocker.categoryLabel}</span>
                      <Chip tone={tone}>{blocker.severity}</Chip>
                      <Chip tone={CONTROL_DOMAIN_TONE[blocker.controlDomain]}>{CONTROL_DOMAIN_LABEL[blocker.controlDomain]}</Chip>
                    </div>
                    <div className="mt-1 truncate text-[11.5px] font-bold text-white/85">{blocker.title}</div>
                  </div>
                  <span className={cn('shrink-0 rounded-lg border px-2.5 py-1 font-mono text-base font-black', t.border, t.soft, t.text)}>{numberFmt(blocker.count)}</span>
                </div>
                <p className="mt-2 line-clamp-2 text-[10px] leading-relaxed text-white/45">{blocker.businessImpact}</p>
                <div className="mt-2 flex flex-wrap items-center gap-x-3 gap-y-1 border-t border-white/8 pt-2 text-[9px] text-white/35">
                  <span className="truncate">Owner: {blocker.owner}</span>
                  <span>·</span>
                  <span>{blocker.affectedAssetIds.length} asset(s)</span>
                  <span className="ml-auto inline-flex items-center gap-1 text-cyan-300 transition group-hover:translate-x-0.5">Remediate <ArrowRight className="h-3 w-3" /></span>
                </div>
              </button>
            );
          })}
        </div>
      )}
    </SectionCard>
  );
}

/* ================================================================== */
/* 9 — Responsibility matrix                                           */
/* ================================================================== */

export function ResponsibilityMatrix({
  rows, controlDomain, onFilterDomain, onExport,
}: {
  rows: ResponsibilityRow[];
  controlDomain: ControlDomain | 'all';
  onFilterDomain: (domain: ControlDomain | 'all') => void;
  onExport: () => void;
}) {
  const [page, setPage] = useState(0);
  const pageSize = 10;
  const pages = Math.max(1, Math.ceil(rows.length / pageSize));
  const current = Math.min(page, pages - 1);
  const visible = rows.slice(current * pageSize, current * pageSize + pageSize);
  useEffect(() => { setPage(0); }, [controlDomain, rows.length]);

  return (
    <SectionCard
      id="responsibility"
      title="Responsibility Matrix"
      icon={Users}
      right={
        <div className="flex items-center gap-1.5">
          {(['all', 'customer', 'provider', 'ecosystem'] as Array<ControlDomain | 'all'>).map((domain) => (
            <button
              key={domain}
              type="button"
              onClick={() => onFilterDomain(domain)}
              aria-pressed={controlDomain === domain}
              className={cn(
                'rounded border px-2 py-1 text-[8.5px] font-black uppercase tracking-wider transition',
                controlDomain === domain ? 'border-cyan-400/50 bg-cyan-500/15 text-cyan-200' : 'border-white/10 bg-white/5 text-white/45 hover:text-cyan-300',
              )}
            >
              {domain === 'all' ? 'All' : CONTROL_DOMAIN_LABEL[domain]}
            </button>
          ))}
          <button type="button" onClick={onExport} title="Export as CSV" className="ml-1 inline-flex items-center gap-1 rounded border border-white/10 bg-white/5 px-2 py-1 text-[9px] font-black uppercase tracking-wider text-white/55 transition hover:text-cyan-300">
            <Download className="h-3 w-3" /> CSV
          </button>
        </div>
      }
    >
      {rows.length === 0 ? (
        <EmptyBlock icon={Users} title="No responsibility rows" detail="The matrix classifies every agility finding into customer-, provider- or ecosystem-controlled ownership. It populates once findings exist." />
      ) : (
        <>
          <div className="overflow-x-auto">
            <table className="w-full min-w-[880px] border-collapse text-left">
              <caption className="sr-only">Responsibility matrix: finding, asset, owner, required user action, priority and control domain.</caption>
              <thead>
                <tr className="border-b border-white/10">
                  {['Finding', 'Asset', 'Owner', 'User Action', 'Priority', 'Control Domain'].map((h) => (
                    <th key={h} scope="col" className="px-2.5 py-2 text-[8.5px] font-black uppercase tracking-[0.14em] text-cyan-300/70">{h}</th>
                  ))}
                </tr>
              </thead>
              <tbody className="divide-y divide-white/5">
                {visible.map((row) => (
                  <tr key={row.id} className="transition hover:bg-cyan-500/[0.04]">
                    <td className="px-2.5 py-2">
                      <div className="max-w-[260px] truncate text-[11px] font-bold text-white/85" title={row.finding}>{row.finding}</div>
                      {row.occurrences > 1 && <div className="mt-0.5 text-[8.5px] text-white/30">{row.occurrences} occurrence(s)</div>}
                    </td>
                    <td className="px-2.5 py-2"><div className="max-w-[160px] truncate text-[10px] text-white/55" title={row.asset}>{row.asset}</div></td>
                    <td className="px-2.5 py-2"><div className="max-w-[140px] truncate text-[10px] text-white/55" title={row.owner}>{row.owner}</div></td>
                    <td className="px-2.5 py-2"><div className="max-w-[280px] truncate text-[10px] text-white/45" title={row.userAction}>{row.userAction}</div></td>
                    <td className="px-2.5 py-2"><Chip tone={SEVERITY_TONE[row.priority]}>{row.priority}</Chip></td>
                    <td className="px-2.5 py-2"><Chip tone={CONTROL_DOMAIN_TONE[row.controlDomain]}>{row.controlDomainLabel}</Chip></td>
                  </tr>
                ))}
              </tbody>
            </table>
          </div>
          {pages > 1 && (
            <div className="mt-3 flex items-center justify-end gap-2 border-t border-white/8 pt-2.5">
              <button type="button" disabled={current === 0} onClick={() => setPage(current - 1)} className="rounded border border-white/10 px-2.5 py-1 text-[9px] font-black uppercase text-white/55 disabled:opacity-30">Prev</button>
              <span className="font-mono text-[9px] text-white/40">Page {current + 1} of {pages}</span>
              <button type="button" disabled={current >= pages - 1} onClick={() => setPage(current + 1)} className="rounded border border-white/10 px-2.5 py-1 text-[9px] font-black uppercase text-white/55 disabled:opacity-30">Next</button>
            </div>
          )}
        </>
      )}
    </SectionCard>
  );
}

/* ================================================================== */
/* 10 — Lifecycle (functional navigation)                              */
/* ================================================================== */

export function AgilityLifecycle({ stages }: { stages: LifecycleStage[] }) {
  return (
    <SectionCard id="lifecycle" title="Crypto Agility Lifecycle" icon={Route} right={<span className="font-mono text-[9px] uppercase tracking-widest text-white/30">{stages.filter((s) => s.status === 'complete').length}/{stages.length} complete</span>}>
      <div className="flex gap-2 overflow-x-auto pb-1">
        {stages.map((stage, index) => {
          const tone: Tone = stage.status === 'complete' ? 'good' : stage.status === 'blocked' ? 'critical' : stage.status === 'active' ? 'neutral' : 'info';
          const t = TONE[tone as PrimitiveTone];
          const isAnchor = stage.route.startsWith('#');
          const content = (
            <>
              <div className="flex items-center gap-1.5">
                <span className="font-mono text-[8px] text-white/25">{String(index + 1).padStart(2, '0')}</span>
                <span className={cn('truncate text-[10.5px] font-black uppercase tracking-wide', t.text)}>{stage.label}</span>
              </div>
              <p className="mt-1 line-clamp-2 text-[9px] leading-relaxed text-white/40">{stage.description}</p>
              <div className="mt-1.5"><Bar value={stage.progressPct} color={TONE_HEX[tone]} height={4} /></div>
              <div className="mt-1 truncate text-[8.5px] text-white/30" title={stage.metric}>{stage.metric}</div>
              <div className="mt-1 truncate text-[8px] font-bold uppercase tracking-wider text-cyan-300/50">{stage.module}</div>
            </>
          );
          return isAnchor ? (
            <button
              key={stage.key}
              type="button"
              onClick={() => document.querySelector(stage.route)?.scrollIntoView({ behavior: 'smooth', block: 'start' })}
              className={cn('min-w-[168px] flex-1 rounded-lg border bg-white/[0.015] p-2.5 text-left transition hover:-translate-y-px hover:border-cyan-400/40', t.border)}
            >
              {content}
            </button>
          ) : (
            <a key={stage.key} href={stage.route} className={cn('min-w-[168px] flex-1 rounded-lg border bg-white/[0.015] p-2.5 no-underline transition hover:-translate-y-px hover:border-cyan-400/40', t.border)}>
              {content}
            </a>
          );
        })}
      </div>
      <p className="mt-2.5 text-[10px] text-white/35">Each stage links to the QGuard Helix module that owns it — this rail is navigation, not decoration.</p>
    </SectionCard>
  );
}

/* ================================================================== */
/* 11 — Runtime telemetry                                              */
/* ================================================================== */

export function RuntimeAgility({ events, live, onInvestigate }: { events: RuntimeCryptoEvent[]; live: boolean; onInvestigate: (event: RuntimeCryptoEvent) => void }) {
  return (
    <SectionCard id="runtime" title="Runtime Crypto Agility" icon={RadioTower} live={live} right={<Chip tone="neutral">{numberFmt(events.length)} event(s)</Chip>}>
      {events.length === 0 ? (
        <EmptyBlock
          icon={RadioTower}
          title="No runtime cryptographic telemetry"
          detail="Without runtime observation, cryptographic changes and drift cannot be detected in production. Runtime Agility is excluded from the score rather than assumed."
          cta={{ label: 'Enable Runtime Telemetry', href: '/dashboard/runtime-telemetry' }}
        />
      ) : (
        <div className="max-h-[340px] space-y-1 overflow-y-auto pr-1 scrollbar-thin">
          {events.map((event) => (
            <div key={event.id} className="grid grid-cols-[auto_minmax(0,1fr)_auto] items-center gap-2.5 rounded-lg border border-white/6 bg-white/[0.015] p-2 transition hover:border-cyan-400/25">
              <span className="h-1.5 w-1.5 shrink-0 rounded-full" style={{ backgroundColor: TONE_HEX[SEVERITY_TONE[event.severity]] }} aria-hidden="true" />
              <div className="min-w-0">
                <div className="flex flex-wrap items-center gap-1.5">
                  <span className="truncate text-[10.5px] font-bold text-white/80">{event.eventType}</span>
                  <Chip tone={SEVERITY_TONE[event.severity]}>{event.severity}</Chip>
                  <span className="truncate font-mono text-[9px] text-cyan-300/70">{event.algorithm}</span>
                </div>
                <div className="mt-0.5 flex flex-wrap items-center gap-x-2 text-[9px] text-white/35">
                  <span className="truncate">{event.asset}</span><span>·</span>
                  <span>{event.source}</span><span>·</span>
                  <span>{relativeTime(event.observedAt)}</span><span>·</span>
                  <span className={event.status === 'Policy violation' ? 'text-red-300' : ''}>{event.status}</span>
                </div>
              </div>
              <button type="button" onClick={() => onInvestigate(event)} className="shrink-0 rounded border border-white/10 bg-white/5 px-2 py-1 text-[8.5px] font-black uppercase tracking-wider text-white/55 transition hover:border-cyan-400/40 hover:text-cyan-300">
                Investigate
              </button>
            </div>
          ))}
        </div>
      )}
    </SectionCard>
  );
}

/* ================================================================== */
/* 12 — Drift                                                          */
/* ================================================================== */

export function AgilityDriftPanel({ drift }: { drift: AgilityDrift }) {
  const tone: Tone = drift.direction === 'improving' ? 'good' : drift.direction === 'critical' ? 'critical' : drift.direction === 'degrading' ? 'warning' : 'info';
  const t = TONE[tone as PrimitiveTone];
  // Plot PQC adoption — the one series measured identically at every historical
  // point. The agility score exists only for "now", so it cannot form a trend.
  const series = drift.trend.map((p) => p.pqcShare).filter((v): v is number => v !== null);

  return (
    <SectionCard id="agility-drift" title="Crypto Agility Drift" icon={drift.direction === 'improving' ? TrendingUp : TrendingDown} right={<Chip tone={tone}>{drift.direction === 'unknown' ? 'Unknown' : drift.direction}</Chip>}>
      <div className="grid gap-4 lg:grid-cols-[minmax(0,1fr)_minmax(0,1.1fr)]">
        <div>
          <div className={cn('rounded-lg border bg-white/[0.02] p-3', t.border)}>
            <div className="text-[8px] font-black uppercase tracking-widest text-white/40">Direction</div>
            <div className={cn('mt-1 text-2xl font-black capitalize leading-none', t.text)}>{drift.direction === 'unknown' ? 'Unknown' : drift.direction}</div>
            <div className="mt-1.5 text-[10px] text-white/45">
              {drift.deltaPoints === null ? drift.windowLabel : `${drift.deltaPoints > 0 ? '+' : ''}${drift.deltaPoints} points · ${drift.windowLabel}`}
            </div>
          </div>
          {series.length > 1 ? (
            <div className="mt-3">
              <div className="mb-1 text-[8px] font-black uppercase tracking-widest text-cyan-300/60">PQC component adoption</div>
              <Sparkline values={series} color={TONE_HEX[tone]} height={54} />
              <div className="mt-1 flex justify-between font-mono text-[8.5px] text-white/25">
                {drift.trend.map((p) => <span key={p.at}>{p.label}</span>)}
              </div>
              <p className="mt-1.5 text-[9.5px] leading-relaxed text-white/30">
                Direction is measured on PQC component adoption — the only series recorded identically at every point. The agility score itself has no historical snapshot, so it is not plotted as a trend.
              </p>
            </div>
          ) : (
            <p className="mt-3 rounded-lg border border-dashed border-white/12 p-3 text-[10px] leading-relaxed text-white/35">
              Not enough dated evidence to plot a trend yet. The series is reconstructed from cryptographic discovery timestamps and needs at least two points.
            </p>
          )}
        </div>

        <div className="space-y-1.5">
          {drift.signals.map((signal) => {
            const st: Tone = signal.tone === 'good' ? 'good' : signal.tone === 'warning' ? 'warning' : signal.tone === 'critical' ? 'critical' : 'info';
            return (
              <div key={signal.label} className="grid grid-cols-[minmax(0,1fr)_auto] items-center gap-2 rounded-lg border border-white/6 bg-white/[0.015] px-3 py-2">
                <div className="min-w-0">
                  <div className="truncate text-[10.5px] font-bold text-white/75">{signal.label}</div>
                  <div className="truncate text-[9px] text-white/35" title={signal.detail}>{signal.detail}</div>
                </div>
                <span className={cn('rounded border px-2 py-0.5 font-mono text-[11px] font-black', TONE[st as PrimitiveTone].border, TONE[st as PrimitiveTone].soft, TONE[st as PrimitiveTone].text)}>{numberFmt(signal.count)}</span>
              </div>
            );
          })}
        </div>
      </div>
      <p className="mt-3 border-t border-white/8 pt-2.5 text-[10px] leading-relaxed text-white/35">{drift.basis}</p>
    </SectionCard>
  );
}

/* ================================================================== */
/* 13 — Policy & governance                                            */
/* ================================================================== */

export function PolicyPanel({ policy }: { policy: PolicyEvaluation }) {
  const [showRules, setShowRules] = useState(false);
  const tone: Tone = policy.compliancePct === null ? 'info' : policy.compliancePct >= 80 ? 'good' : policy.compliancePct >= 50 ? 'warning' : 'critical';

  return (
    <SectionCard
      id="agility-policy"
      title="Crypto Agility Policy & Governance"
      icon={Lock}
      right={<Chip tone={tone}>{policy.compliancePct === null ? 'Not evaluated' : `${policy.compliancePct}% compliant`}</Chip>}
    >
      <div className="grid gap-3 sm:grid-cols-2 lg:grid-cols-4">
        <MiniField label="Active policy" value={policy.policyName} />
        <MiniField label="Version" value={policy.version} />
        <MiniField label="Last evaluated" value={relativeTime(policy.lastEvaluatedAt)} />
        <MiniField label="Exceptions" value={`${policy.exceptions.length} recorded`} />
      </div>

      {policy.violations.length === 0 ? (
        <div className="mt-3 rounded-lg border border-emerald-500/25 bg-emerald-500/[0.06] p-3">
          <div className="flex items-center gap-2 text-[11px] font-black uppercase tracking-wider text-emerald-300">
            <BadgeCheck className="h-4 w-4" /> No policy violations in the evaluated evidence
          </div>
          <p className="mt-1 text-[10px] text-white/40">{policy.basis}</p>
        </div>
      ) : (
        <div className="mt-3 space-y-1.5">
          {policy.violations.map((violation) => (
            <div key={violation.ruleId} className={cn('grid grid-cols-[minmax(0,1fr)_auto] items-center gap-3 rounded-lg border bg-white/[0.015] px-3 py-2', TONE[SEVERITY_TONE[violation.severity] as PrimitiveTone].border)}>
              <div className="min-w-0">
                <div className="flex flex-wrap items-center gap-1.5">
                  <span className="font-mono text-[11px] font-black text-white/85">{violation.subject}</span>
                  <Chip tone={SEVERITY_TONE[violation.severity]}>{violation.verdict}</Chip>
                </div>
                <div className="mt-0.5 truncate font-mono text-[9.5px] text-cyan-300/60" title={violation.observed}>Observed: {violation.observed}</div>
                <div className="mt-0.5 line-clamp-1 text-[9.5px] text-white/40">{violation.remediation}</div>
              </div>
              <div className="shrink-0 text-right">
                <div className="font-mono text-[13px] font-black text-white/85">{numberFmt(violation.assets)}</div>
                <div className="text-[8px] uppercase tracking-wider text-white/30">asset(s)</div>
              </div>
            </div>
          ))}
        </div>
      )}

      {policy.exceptions.length > 0 && (
        <div className="mt-3 rounded-lg border border-white/8 bg-black/20 p-2.5">
          <div className="mb-1.5 text-[8.5px] font-black uppercase tracking-widest text-cyan-300/70">Recorded exceptions</div>
          <div className="space-y-1">
            {policy.exceptions.slice(0, 5).map((exception) => (
              <div key={exception.id} className="flex flex-wrap items-center gap-2 text-[10px] text-white/50">
                <Chip tone="warning">{exception.status}</Chip>
                <span className="truncate">{exception.policy}</span>
                {exception.expiresAt && <span className="text-white/30">· expires {relativeTime(exception.expiresAt)}</span>}
              </div>
            ))}
          </div>
        </div>
      )}

      <button type="button" onClick={() => setShowRules((v) => !v)} className="mt-3 inline-flex items-center gap-1.5 text-[10px] font-black uppercase tracking-wider text-cyan-300 hover:text-cyan-200">
        <ChevronDown className={cn('h-3.5 w-3.5 transition-transform', showRules && 'rotate-180')} />
        {showRules ? 'Hide policy rules' : `Show all ${policy.rules.length} policy rules`}
      </button>
      <AnimatePresence initial={false}>
        {showRules && (
          <motion.div initial={{ height: 0, opacity: 0 }} animate={{ height: 'auto', opacity: 1 }} exit={{ height: 0, opacity: 0 }} className="overflow-hidden">
            <div className="mt-2 grid gap-1.5 sm:grid-cols-2">
              {policy.rules.map((rule) => (
                <div key={rule.id} className="rounded border border-white/8 bg-black/20 px-2.5 py-1.5">
                  <div className="flex items-center justify-between gap-2">
                    <span className="truncate font-mono text-[10px] font-bold text-white/80">{rule.subject}</span>
                    <Chip tone={rule.verdict === 'block' ? 'critical' : rule.verdict === 'warn' ? 'warning' : rule.verdict === 'preferred' || rule.verdict === 'required' ? 'good' : 'info'}>{rule.verdict}</Chip>
                  </div>
                  <div className="mt-0.5 text-[9px] leading-relaxed text-white/35">{rule.rationale}</div>
                  <div className="mt-0.5 text-[8.5px] uppercase tracking-wider text-cyan-300/40">{rule.standard}</div>
                </div>
              ))}
            </div>
          </motion.div>
        )}
      </AnimatePresence>
    </SectionCard>
  );
}

function MiniField({ label, value }: { label: string; value: string }) {
  return (
    <div className="rounded-lg border border-white/8 bg-black/20 px-2.5 py-2">
      <div className="text-[8px] font-black uppercase tracking-widest text-cyan-300/60">{label}</div>
      <div className="mt-0.5 truncate text-[11px] font-bold text-white/75" title={value}>{value}</div>
    </div>
  );
}

/* ================================================================== */
/* 14 — Assessment history                                             */
/* ================================================================== */

export function AssessmentHistory({ history }: { history: AssessmentHistoryPoint[] }) {
  if (history.length === 0) {
    return (
      <SectionCard id="history" title="Assessment History" icon={Activity}>
        <EmptyBlock
          icon={Activity}
          title="No assessment history yet"
          detail="History is reconstructed from the discovery timestamps on your own cryptographic evidence. At least two dated evidence points are required."
          cta={{ label: 'Run Discovery Scan', href: '/dashboard/scanner' }}
        />
      </SectionCard>
    );
  }

  // The bar series is PQC ADOPTION, which is measured identically at every
  // point. The agility score exists only for the live point, so it is reported
  // in the table rather than drawn as a trend it cannot support.
  const max = Math.max(...history.map((p) => p.pqcAdoptionPct ?? 0), 1);

  return (
    <SectionCard
      id="history"
      title="Assessment History"
      icon={Activity}
      right={<Chip tone="info">{history.length} point(s)</Chip>}
    >
      <div className="mb-1 text-[8px] font-black uppercase tracking-widest text-cyan-300/60">PQC component adoption over time</div>
      <div className="flex items-end gap-2 pb-2">
        {history.map((point) => {
          const value = point.pqcAdoptionPct ?? 0;
          const height = Math.max(6, (value / max) * 110);
          return (
            <div
              key={point.at}
              className="group flex flex-1 flex-col items-center gap-1"
              title={`${point.label}: PQC adoption ${pctFmt(point.pqcAdoptionPct)}, vulnerable share ${pctFmt(point.vulnerableSharePct)}${point.reconstructed ? ' (reconstructed from discovery timestamps)' : ' (live assessment)'}`}
            >
              <span className="font-mono text-[10px] font-black text-white/70">{pctFmt(point.pqcAdoptionPct)}</span>
              <div
                className="w-full rounded-t transition-all duration-700"
                style={{
                  height,
                  background: point.reconstructed
                    ? 'repeating-linear-gradient(45deg, rgba(34,211,238,0.35) 0 4px, rgba(34,211,238,0.12) 4px 8px)'
                    : 'linear-gradient(180deg, #22d3ee, rgba(34,211,238,0.25))',
                }}
              />
              <span className="truncate text-[8.5px] font-bold uppercase tracking-wider text-white/35">{point.label}</span>
            </div>
          );
        })}
      </div>

      <div className="mt-2 overflow-x-auto">
        <table className="w-full min-w-[720px] border-collapse text-left">
          <caption className="sr-only">
            Assessment history by date with PQC component adoption, quantum-vulnerable share, agility score, migration readiness, blockers, policy compliance and the basis of each point.
          </caption>
          <thead>
            <tr className="border-b border-white/10">
              {['Date', 'PQC Adoption', 'Vulnerable Share', 'Agility Score', 'Migration Readiness', 'Blockers', 'Policy Compliance', 'Basis'].map((h) => (
                <th key={h} scope="col" className="px-2.5 py-1.5 text-[8.5px] font-black uppercase tracking-[0.14em] text-cyan-300/70">{h}</th>
              ))}
            </tr>
          </thead>
          <tbody className="divide-y divide-white/5">
            {history.map((point) => (
              <tr key={point.at}>
                <td className="px-2.5 py-1.5 text-[10px] text-white/60">{point.label}</td>
                <td className="px-2.5 py-1.5 font-mono text-[10px] font-bold text-white/80">{pctFmt(point.pqcAdoptionPct)}</td>
                <td className="px-2.5 py-1.5 font-mono text-[10px] text-white/60">{pctFmt(point.vulnerableSharePct)}</td>
                <td className="px-2.5 py-1.5 font-mono text-[10px] text-white/60" title={point.reconstructed ? 'The agility score depends on coupling, ownership and dependency evidence that has no historical snapshot.' : undefined}>
                  {point.reconstructed ? 'Not recorded' : scoreFmt(point.agilityScore)}
                </td>
                <td className="px-2.5 py-1.5 font-mono text-[10px] text-white/60">{point.reconstructed ? '—' : pctFmt(point.migrationReadinessPct)}</td>
                <td className="px-2.5 py-1.5 font-mono text-[10px] text-white/60">{point.reconstructed ? '—' : numberFmt(point.blockers)}</td>
                <td className="px-2.5 py-1.5 font-mono text-[10px] text-white/60">{point.reconstructed ? '—' : pctFmt(point.policyCompliancePct)}</td>
                <td className="px-2.5 py-1.5">
                  <Chip tone={point.reconstructed ? 'info' : 'good'}>{point.reconstructed ? 'Reconstructed' : 'Live assessment'}</Chip>
                </td>
              </tr>
            ))}
          </tbody>
        </table>
      </div>

      <p className="mt-2.5 border-t border-white/8 pt-2.5 text-[10px] leading-relaxed text-white/35">
        Points marked <span className="text-cyan-300/70">Reconstructed</span> are computed from the discovery timestamps on your own cryptographic evidence — real tenant history, labelled so it is never mistaken for a recorded assessment. They carry the component shares that <em>were</em> measurable then, and deliberately no agility score: coupling, ownership and dependency evidence has no historical snapshot, so back-filling one would compare two different scales.
      </p>
    </SectionCard>
  );
}

/* ================================================================== */
/* 15 — Sophia recommendations                                         */
/* ================================================================== */

export function SophiaRecommendations({
  recommendations, onAsk, onAct,
}: {
  recommendations: AgilityRecommendation[];
  onAsk: (question: string) => void;
  onAct: (rec: AgilityRecommendation) => void;
}) {
  return (
    <SectionCard
      id="sophia"
      title="Sophia — Crypto Agility Recommendations"
      icon={Sparkles}
      right={<Chip tone="ai">{recommendations.length} prioritised</Chip>}
    >
      {recommendations.length === 0 ? (
        <EmptyBlock icon={Sparkles} title="No recommendations yet" detail="Sophia builds agility recommendations from your own blockers, coupling findings and domain scores. They appear once evidence exists." cta={{ label: 'Run Discovery Scan', href: '/dashboard/scanner' }} />
      ) : (
        <div className="space-y-2">
          {recommendations.map((rec) => (
            <div key={rec.id} className="rounded-lg border border-violet-400/20 bg-violet-500/[0.05] p-3">
              <div className="flex flex-wrap items-start justify-between gap-2">
                <div className="min-w-0">
                  <div className="flex flex-wrap items-center gap-1.5">
                    <Sparkles className="h-3 w-3 shrink-0 text-violet-300" />
                    <span className="truncate text-[11.5px] font-black text-white/90">{rec.title}</span>
                    <Chip tone={SEVERITY_TONE[rec.severity]}>{rec.severity}</Chip>
                    <Chip tone={CONTROL_DOMAIN_TONE[rec.controlDomain]}>{CONTROL_DOMAIN_LABEL[rec.controlDomain]}</Chip>
                  </div>
                  <p className="mt-1.5 text-[10.5px] leading-relaxed text-white/50">{rec.detail}</p>
                </div>
                <div className="flex shrink-0 gap-2">
                  {rec.expectedScoreGain > 0 && (
                    <div className="rounded-lg border border-emerald-400/25 bg-emerald-500/10 px-2.5 py-1.5 text-center">
                      <div className="font-mono text-[15px] font-black text-emerald-300">+{rec.expectedScoreGain}</div>
                      <div className="text-[7.5px] font-black uppercase tracking-wider text-white/35">agility pts</div>
                    </div>
                  )}
                  <div className="rounded-lg border border-white/10 bg-black/25 px-2.5 py-1.5 text-center">
                    <div className="font-mono text-[15px] font-black text-white/80">{numberFmt(rec.affectedAssets)}</div>
                    <div className="text-[7.5px] font-black uppercase tracking-wider text-white/35">assets</div>
                  </div>
                  {rec.dependencyReductionPct !== null && (
                    <div className="hidden rounded-lg border border-white/10 bg-black/25 px-2.5 py-1.5 text-center sm:block">
                      <div className="font-mono text-[15px] font-black text-cyan-300">{rec.dependencyReductionPct}%</div>
                      <div className="text-[7.5px] font-black uppercase tracking-wider text-white/35">dep. share</div>
                    </div>
                  )}
                </div>
              </div>

              {rec.evidence.length > 0 && (
                <div className="mt-2 rounded border border-white/8 bg-black/25 p-2">
                  <div className="mb-1 text-[8px] font-black uppercase tracking-widest text-violet-300/70">Supporting evidence</div>
                  <ul className="space-y-0.5">
                    {rec.evidence.slice(0, 4).map((line, index) => (
                      <li key={index} className="truncate font-mono text-[9px] text-white/40" title={line}>· {line}</li>
                    ))}
                  </ul>
                </div>
              )}

              <div className="mt-2 flex flex-wrap items-center gap-2">
                <button type="button" onClick={() => onAct(rec)} className="inline-flex items-center gap-1.5 rounded border border-cyan-400/40 bg-cyan-500/15 px-2.5 py-1.5 text-[9px] font-black uppercase tracking-wider text-cyan-200 transition hover:bg-cyan-500/25">
                  {rec.action} <ArrowRight className="h-3 w-3" />
                </button>
                <button type="button" onClick={() => onAsk(`${rec.title} — explain the evidence behind this recommendation and what it would take to complete it.`)} className="inline-flex items-center gap-1.5 rounded border border-violet-400/40 bg-violet-500/10 px-2.5 py-1.5 text-[9px] font-black uppercase tracking-wider text-violet-200 transition hover:bg-violet-500/20">
                  <Sparkles className="h-3 w-3" /> Ask Sophia
                </button>
              </div>
            </div>
          ))}
        </div>
      )}
      <p className="mt-3 border-t border-white/8 pt-2.5 text-[10px] leading-relaxed text-white/35">
        Recommendations are derived from your own tenant evidence and cite the assets behind them. Expected score gain is the share of the affected domain's remaining headroom that clearing the blocker recovers — a projection, not a guarantee.
      </p>
    </SectionCard>
  );
}

/* ================================================================== */
/* 16 — Filter bar                                                     */
/* ================================================================== */

export function AgilityFilterBar({
  filters, options, activeCount, onChange, onClear,
}: {
  filters: AgilityFilters;
  options: CryptoAgilityIntelligence['filters'];
  activeCount: number;
  onChange: (patch: Partial<AgilityFilters>) => void;
  onClear: () => void;
}) {
  return (
    <Panel className="p-3">
      <div className="flex flex-wrap items-center gap-2">
        <label className="relative min-w-[190px] flex-1">
          <span className="sr-only">Search assets, owners and algorithms</span>
          <Search className="pointer-events-none absolute left-2.5 top-1/2 h-3.5 w-3.5 -translate-y-1/2 text-white/30" />
          <input
            value={filters.search}
            onChange={(e) => onChange({ search: e.target.value })}
            placeholder="Search assets, owners, algorithms…"
            className="h-8 w-full rounded-lg border border-white/10 bg-black/30 pl-8 pr-2.5 text-[11px] text-white/85 placeholder:text-white/25 focus:border-cyan-400/50 focus:outline-none"
          />
        </label>

        <Select label="Agility state" value={filters.state} onChange={(v) => onChange({ state: v as AgilityFilters['state'] })}
          options={[['all', 'All states'], ['agile', 'Agile'], ['conditional', 'Conditional'], ['rigid', 'Rigid'], ['blocked', 'Blocked'], ['unknown', 'Unknown']]} />

        <Select label="Migration readiness" value={filters.readiness} onChange={(v) => onChange({ readiness: v as AgilityFilters['readiness'] })}
          options={[['all', 'All readiness'], ['ready', 'Ready'], ['conditional', 'Conditionally Ready'], ['blocked', 'Blocked'], ['unknown', 'Unknown']]} />

        <Select label="Replaceability" value={filters.replaceability} onChange={(v) => onChange({ replaceability: v as AgilityFilters['replaceability'] })}
          options={[['all', 'All replaceability'], ['configuration', 'Configuration only'], ['library', 'Library upgrade'], ['code', 'Code modification'], ['architecture', 'Architecture change'], ['vendor', 'Vendor dependency'], ['unknown', 'Unknown']]} />

        <Select label="Environment" value={filters.environment} onChange={(v) => onChange({ environment: v })}
          options={[['all', 'All environments'], ...options.environments.map((e) => [e, e] as [string, string])]} />

        <Select label="Owner" value={filters.owner} onChange={(v) => onChange({ owner: v })}
          options={[['all', 'All owners'], ...options.owners.slice(0, 60).map((o) => [o, o] as [string, string])]} />

        <Select label="Control domain" value={filters.controlDomain} onChange={(v) => onChange({ controlDomain: v as AgilityFilters['controlDomain'] })}
          options={[['all', 'All control domains'], ['customer', 'Customer-Controlled'], ['provider', 'Provider-Controlled'], ['ecosystem', 'Ecosystem-Dependent']]} />

        <Select label="Algorithm" value={filters.algorithm} onChange={(v) => onChange({ algorithm: v })}
          options={[['all', 'All algorithms'], ...options.algorithms.slice(0, 80).map((a) => [a, a] as [string, string])]} />

        {activeCount > 0 && (
          <button type="button" onClick={onClear} className="inline-flex items-center gap-1.5 rounded-lg border border-cyan-400/40 bg-cyan-500/10 px-2.5 py-1.5 text-[9px] font-black uppercase tracking-wider text-cyan-200">
            Clear {activeCount} filter{activeCount === 1 ? '' : 's'}
          </button>
        )}
      </div>
    </Panel>
  );
}

function Select({ label, value, onChange, options }: { label: string; value: string; onChange: (value: string) => void; options: Array<[string, string]> }) {
  return (
    <label className="relative">
      <span className="sr-only">{label}</span>
      <select
        value={value}
        onChange={(e) => onChange(e.target.value)}
        aria-label={label}
        className="h-8 max-w-[190px] rounded-lg border border-white/10 bg-black/30 px-2.5 text-[10.5px] font-semibold text-white/75 focus:border-cyan-400/50 focus:outline-none"
      >
        {options.map(([v, l]) => (
          <option key={v} value={v} className="bg-[#0b1120] text-white">{l}</option>
        ))}
      </select>
    </label>
  );
}

/* ================================================================== */
/* 17 — Graph section shell                                            */
/* ================================================================== */

export function GraphSection({ children, note }: { children: ReactNode; note: string }) {
  return (
    <SectionCard id="coupling-graph" title="Crypto Dependency & Coupling Graph" icon={GitBranch} right={<Chip tone="info" title={note}><Link2 className="h-2.5 w-2.5" /> projection</Chip>}>
      {children}
    </SectionCard>
  );
}

/* ================================================================== */
/* 18 — Change test (sandbox hand-off)                                 */
/* ================================================================== */

export { Workflow, Play, ListChecks, Activity };
