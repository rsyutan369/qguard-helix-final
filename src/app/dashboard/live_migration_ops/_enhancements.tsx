'use client'

import { Link } from 'react-router-dom'
import {
  ArrowRight,
  Award,
  BadgeCheck,
  BrainCircuit,
  CalendarClock,
  CheckCircle2,
  Clock3,
  Download,
  Gauge,
  PartyPopper,
  ShieldCheck,
  Sparkles,
  TrendingDown,
  Zap,
} from 'lucide-react'

/**
 * Live Migration — enterprise enhancement band (additive, per
 * Qguard_Wiki/Live_Migration_Enhancements). Reframes the operations page around
 * business outcomes without redesigning the existing job/telemetry surface:
 * Quantum Migration Progress hero, Executive KPIs, a live Before → After
 * Cryptographic Upgrade panel, the deterministic AI Migration Advisor, a
 * Quantum Certification progress checklist, a 6-step story strip, and a final
 * success celebration.
 *
 * Every value is passed in already-derived from the page's REAL live-migration
 * snapshot + shared workflow state — nothing here fabricates metrics.
 */

const PANEL = 'rounded-2xl border border-white/10 bg-white/[0.035] backdrop-blur-xl text-white shadow-[0_18px_60px_rgba(0,0,0,0.35)]'
const INNER = 'rounded-xl border border-white/10 bg-white/[0.02]'
const CYAN = '#22d3ee'
const EMERALD = '#34d399'

function fmt(n: number) {
  return new Intl.NumberFormat('en-US').format(Math.round(n || 0))
}

/* ---- prop contracts (self-contained; page computes these from real data) ---- */
export interface MigrationProgress {
  pct: number
  migrated: number
  remaining: number
  verified: number
  total: number
  inProgress: number
  failed: number
  etaLabel: string
  speedLabel: string | null
}
export interface ExecKpi {
  label: string
  value: string
  hint: string
  tone: string
}
export interface CryptoTransition {
  from: string
  to: string
  count: number
  standard: string
  detected: boolean
}
export interface MigrationAdvisor {
  headline: string
  lines: string[]
  recommendation: string
  residualRisk: string
  residualTone: string
  maintenanceWindow: string
  estEffort: string
  route: string
}
export interface CertProgress {
  pct: number
  eligible: boolean
  domains: Array<{ label: string; status: 'done' | 'running' | 'pending' }>
}
export interface StoryStep {
  label: string
  value: string
  active: boolean
  done: boolean
}
export interface SuccessState {
  show: boolean
  assetsProtected: number
  highlights: string[]
}

export interface LiveMigrationEnhancementsProps {
  progress: MigrationProgress
  readinessPct: number
  kpis: ExecKpi[]
  transitions: CryptoTransition[]
  advisor: MigrationAdvisor
  certification: CertProgress
  story: StoryStep[]
  success: SuccessState
}

/* ------------------------------------------------------------------ */
/* Progress ring                                                       */
/* ------------------------------------------------------------------ */
function Ring({ pct, size = 132, stroke = 12, color, label, sublabel }: { pct: number; size?: number; stroke?: number; color: string; label: string; sublabel: string }) {
  const r = (size - stroke) / 2
  const c = 2 * Math.PI * r
  return (
    <div className="relative grid shrink-0 place-items-center" style={{ width: size, height: size }}>
      <svg width={size} height={size} viewBox={`0 0 ${size} ${size}`} className="-rotate-90">
        <circle cx={size / 2} cy={size / 2} r={r} fill="none" stroke="rgba(255,255,255,0.08)" strokeWidth={stroke} />
        <circle cx={size / 2} cy={size / 2} r={r} fill="none" stroke={color} strokeWidth={stroke} strokeLinecap="round" strokeDasharray={c} strokeDashoffset={c * (1 - Math.min(100, pct) / 100)} style={{ transition: 'stroke-dashoffset 1s ease' }} />
      </svg>
      <div className="absolute inset-0 grid place-items-center text-center">
        <div>
          <div className="text-3xl font-black tabular-nums text-white">{label}</div>
          <div className="text-[10px] font-bold uppercase tracking-wide text-white/40">{sublabel}</div>
        </div>
      </div>
    </div>
  )
}

/* ------------------------------------------------------------------ */
/* Main band                                                           */
/* ------------------------------------------------------------------ */
export default function LiveMigrationEnhancements(props: LiveMigrationEnhancementsProps) {
  const { progress, readinessPct, kpis, transitions, advisor, certification, story, success } = props
  const progressColor = progress.pct >= 100 ? EMERALD : progress.pct >= 60 ? '#38bdf8' : progress.pct >= 25 ? '#f59e0b' : '#fb923c'

  return (
    <div className="space-y-3">
      {/* Final success celebration */}
      {success.show ? (
        <section className={`${PANEL} relative overflow-hidden p-6`} style={{ background: 'radial-gradient(120% 140% at 10% 0%, rgba(52,211,153,0.14), transparent 55%), rgba(255,255,255,0.035)' }}>
          <div className="flex flex-col gap-4 lg:flex-row lg:items-center lg:justify-between">
            <div className="flex items-center gap-4">
              <div className="grid h-14 w-14 place-items-center rounded-2xl border border-emerald-400/40 bg-emerald-400/15 text-emerald-300">
                <PartyPopper className="h-7 w-7" />
              </div>
              <div>
                <div className="flex items-center gap-2 text-lg font-black text-white">Enterprise Successfully Upgraded <BadgeCheck className="h-5 w-5 text-emerald-300" /></div>
                <div className="mt-0.5 text-sm text-white/60">{fmt(success.assetsProtected)} assets protected · Quantum Trust Certification earned</div>
                <div className="mt-1 flex flex-wrap gap-1.5">
                  {success.highlights.map((h) => (
                    <span key={h} className="rounded-full border border-emerald-400/25 bg-emerald-400/10 px-2 py-0.5 text-[10px] font-bold text-emerald-200">{h}</span>
                  ))}
                </div>
              </div>
            </div>
            <Link to="/dashboard/quantum-certification" className="inline-flex items-center gap-2 rounded-xl border border-emerald-400/40 bg-emerald-400/15 px-5 py-2.5 text-sm font-black text-emerald-200 no-underline transition hover:bg-emerald-400/25">
              <Download className="h-4 w-4" /> Download Certificate
            </Link>
          </div>
        </section>
      ) : null}

      {/* Quantum Migration Progress hero — the business outcome, front and center */}
      <section className={`${PANEL} grid gap-5 p-5 lg:grid-cols-[minmax(0,340px)_1fr]`}>
        <div className="flex items-center gap-5">
          <Ring pct={readinessPct} color={progressColor} label={`${readinessPct}%`} sublabel="Quantum Ready" />
          <div className="min-w-0">
            <div className="flex items-center gap-1.5 text-[10px] font-black uppercase tracking-[0.14em] text-white/45">
              <Gauge className="h-3.5 w-3.5 text-cyan-300" /> Quantum Migration Progress
            </div>
            <div className="mt-2 text-2xl font-black text-white">{progress.pct}% migrated</div>
            <div className="mt-2 h-2.5 w-full overflow-hidden rounded-full bg-white/10">
              <div className="h-full rounded-full transition-all duration-1000" style={{ width: `${Math.min(100, progress.pct)}%`, backgroundColor: progressColor }} />
            </div>
            <div className="mt-2 flex flex-wrap items-center gap-x-4 gap-y-1 text-[11px] text-white/55">
              <span><b className="text-white">{fmt(progress.migrated)}</b> migrated</span>
              <span><b className="text-white">{fmt(progress.remaining)}</b> remaining</span>
              <span className="inline-flex items-center gap-1"><Clock3 className="h-3 w-3 text-cyan-300" /> ETA {progress.etaLabel}</span>
            </div>
          </div>
        </div>
        <div className="grid grid-cols-2 gap-2 sm:grid-cols-3">
          {[
            { label: 'Quantum Secure', value: fmt(progress.verified), tone: EMERALD, hint: 'Validated & protected' },
            { label: 'In Progress', value: fmt(progress.inProgress), tone: CYAN, hint: 'Migrating now' },
            { label: 'Remaining', value: fmt(progress.remaining), tone: '#f59e0b', hint: 'Awaiting upgrade' },
            { label: 'Needs Attention', value: fmt(progress.failed), tone: '#f87171', hint: 'Failed / review' },
            { label: 'Migration Speed', value: progress.speedLabel || '—', tone: '#a78bfa', hint: 'Assets / min' },
            { label: 'Est. Completion', value: progress.etaLabel, tone: '#38bdf8', hint: 'At current rate' },
          ].map((c) => (
            <div key={c.label} className={`${INNER} p-3`}>
              <div className="text-2xl font-black tabular-nums" style={{ color: c.tone }}>{c.value}</div>
              <div className="mt-0.5 text-[10px] font-bold uppercase tracking-wide text-white/45">{c.label}</div>
              <div className="text-[10px] text-white/30">{c.hint}</div>
            </div>
          ))}
        </div>
      </section>

      {/* Executive KPIs */}
      <section className={`${PANEL} p-5`}>
        <div className="mb-3 flex items-center gap-2">
          <TrendingDown className="h-4 w-4 text-emerald-300" />
          <h3 className="text-sm font-black uppercase tracking-wide text-white/80">Executive Outcomes</h3>
        </div>
        <div className="grid grid-cols-2 gap-2 sm:grid-cols-3 xl:grid-cols-5">
          {kpis.map((k) => (
            <div key={k.label} className={`${INNER} p-3`}>
              <div className="text-xl font-black tabular-nums" style={{ color: k.tone }}>{k.value}</div>
              <div className="mt-0.5 text-[10px] font-bold uppercase tracking-wide text-white/45">{k.label}</div>
              <div className="text-[10px] text-white/30">{k.hint}</div>
            </div>
          ))}
        </div>
      </section>

      <div className="grid gap-3 xl:grid-cols-[minmax(0,1fr)_minmax(340px,0.8fr)]">
        {/* Before → After cryptographic upgrade */}
        <section className={`${PANEL} p-5`}>
          <div className="mb-1 flex items-center gap-2">
            <Sparkles className="h-4 w-4 text-cyan-300" />
            <h3 className="text-sm font-black uppercase tracking-wide text-white/80">Cryptographic Upgrade — Before → After</h3>
          </div>
          <p className="mb-3 text-[11px] text-white/45">Quantum-vulnerable primitives transformed into NIST post-quantum equivalents (FIPS 203/204/205, CNSA 2.0).</p>
          <div className="space-y-2">
            {transitions.map((t) => (
              <div key={`${t.from}->${t.to}`} className={`${INNER} flex items-center gap-3 p-3`}>
                <div className="min-w-0 flex-1">
                  <div className="grid grid-cols-[1fr_auto_1fr] items-center gap-2">
                    <span className="truncate rounded-lg border border-red-400/25 bg-red-400/[0.07] px-2.5 py-1.5 text-center font-mono text-[11px] font-bold text-red-200">{t.from}</span>
                    <span className="relative grid h-6 w-8 place-items-center overflow-hidden">
                      <ArrowRight className="h-4 w-4 text-cyan-300" />
                      <span className="pointer-events-none absolute inset-0 -translate-x-full animate-[shimmer_2.2s_linear_infinite] bg-gradient-to-r from-transparent via-cyan-400/50 to-transparent" />
                    </span>
                    <span className="truncate rounded-lg border border-emerald-400/25 bg-emerald-400/[0.07] px-2.5 py-1.5 text-center font-mono text-[11px] font-bold text-emerald-200">{t.to}</span>
                  </div>
                  <div className="mt-1 flex items-center justify-between text-[10px] text-white/35">
                    <span>{t.standard}</span>
                    <span>{t.detected ? `${fmt(t.count)} asset${t.count === 1 ? '' : 's'}` : 'Standard upgrade path'}</span>
                  </div>
                </div>
              </div>
            ))}
          </div>
          <style>{`@keyframes shimmer { 0% { transform: translateX(-100%) } 100% { transform: translateX(100%) } }`}</style>
        </section>

        {/* AI Migration Advisor */}
        <section className={`${PANEL} flex flex-col p-5`}>
          <div className="mb-1 flex items-center gap-2">
            <BrainCircuit className="h-4 w-4 text-violet-300" />
            <h3 className="text-sm font-black uppercase tracking-wide text-white/80">AI Migration Advisor</h3>
          </div>
          <div className="mb-3 rounded-xl border border-violet-400/25 bg-violet-400/[0.06] p-3">
            <div className="text-sm font-bold text-violet-100">{advisor.headline}</div>
            <div className="mt-1 text-[12px] text-white/60">{advisor.recommendation}</div>
          </div>
          <div className="space-y-2 text-[12px] text-white/60">
            {advisor.lines.map((line, i) => (
              <div key={i} className="flex items-start gap-2">
                <CheckCircle2 className="mt-0.5 h-3.5 w-3.5 shrink-0 text-cyan-300" /> <span>{line}</span>
              </div>
            ))}
          </div>
          <div className="mt-3 grid grid-cols-2 gap-2">
            <div className={`${INNER} p-3`}>
              <div className="flex items-center gap-1.5 text-[10px] font-bold uppercase tracking-wide text-white/40"><CalendarClock className="h-3 w-3" /> Suggested Window</div>
              <div className="mt-1 text-sm font-bold text-white/85">{advisor.maintenanceWindow}</div>
            </div>
            <div className={`${INNER} p-3`}>
              <div className="flex items-center gap-1.5 text-[10px] font-bold uppercase tracking-wide text-white/40"><ShieldCheck className="h-3 w-3" /> Residual Risk</div>
              <div className="mt-1 text-sm font-black" style={{ color: advisor.residualTone }}>{advisor.residualRisk}</div>
            </div>
          </div>
          <div className="mt-3 flex items-center justify-between text-[11px] text-white/45">
            <span className="inline-flex items-center gap-1"><Zap className="h-3 w-3 text-cyan-300" /> Est. effort {advisor.estEffort}</span>
            <Link to={advisor.route} className="inline-flex items-center gap-1 font-bold text-cyan-300 no-underline hover:text-cyan-200">Open roadmap <ArrowRight className="h-3 w-3" /></Link>
          </div>
        </section>
      </div>

      <div className="grid gap-3 lg:grid-cols-[minmax(0,1fr)_minmax(320px,0.72fr)]">
        {/* Story strip */}
        <section className={`${PANEL} p-5`}>
          <div className="mb-3 flex items-center gap-2">
            <Award className="h-4 w-4 text-cyan-300" />
            <h3 className="text-sm font-black uppercase tracking-wide text-white/80">The Migration Story</h3>
          </div>
          <div className="flex flex-wrap items-stretch gap-1.5">
            {story.map((s, i) => (
              <div key={s.label} className="flex items-center gap-1.5">
                <div className={`min-w-[92px] rounded-xl border px-2.5 py-2 ${s.active ? 'border-cyan-400/50 bg-cyan-400/10' : s.done ? 'border-emerald-400/30 bg-emerald-400/[0.06]' : 'border-white/8 bg-white/[0.02]'}`}>
                  <div className="flex items-center gap-1 text-[9px] font-black uppercase tracking-wide" style={{ color: s.active ? CYAN : s.done ? EMERALD : 'rgba(255,255,255,0.4)' }}>
                    {s.done ? <CheckCircle2 className="h-3 w-3" /> : <span>{i + 1}</span>} {s.label}
                  </div>
                  <div className="mt-0.5 text-sm font-black text-white">{s.value}</div>
                </div>
                {i < story.length - 1 ? <ArrowRight className="h-3.5 w-3.5 shrink-0 text-white/25" /> : null}
              </div>
            ))}
          </div>
        </section>

        {/* Quantum Certification progress */}
        <section className={`${PANEL} p-5`}>
          <div className="mb-3 flex items-center justify-between">
            <h3 className="inline-flex items-center gap-2 text-sm font-black uppercase tracking-wide text-white/80"><Award className="h-4 w-4 text-amber-300" /> Certification Progress</h3>
            <span className="text-sm font-black tabular-nums" style={{ color: certification.eligible ? EMERALD : '#f59e0b' }}>{certification.pct}%</span>
          </div>
          <div className="mb-3 h-2 overflow-hidden rounded-full bg-white/10">
            <div className="h-full rounded-full transition-all duration-1000" style={{ width: `${Math.min(100, certification.pct)}%`, backgroundColor: certification.eligible ? EMERALD : '#f59e0b' }} />
          </div>
          <div className="grid grid-cols-2 gap-1.5">
            {certification.domains.map((d) => (
              <div key={d.label} className="flex items-center justify-between rounded-lg border border-white/8 bg-white/[0.02] px-2.5 py-1.5">
                <span className="text-[11px] font-semibold text-white/70">{d.label}</span>
                {d.status === 'done' ? <CheckCircle2 className="h-3.5 w-3.5 text-emerald-300" /> : d.status === 'running' ? <span className="text-[9px] font-black uppercase text-cyan-300">Running</span> : <span className="text-[9px] font-black uppercase text-white/30">Pending</span>}
              </div>
            ))}
          </div>
          {certification.eligible ? (
            <div className="mt-3 flex items-center gap-2 rounded-xl border border-amber-400/30 bg-amber-400/[0.08] px-3 py-2 text-[12px] font-bold text-amber-200">
              <Award className="h-4 w-4" /> Enterprise Quantum Certified — eligible to issue.
            </div>
          ) : null}
        </section>
      </div>
    </div>
  )
}
