/**
 * Quantum Readiness Assessment — marketing overview (/quantum-readiness-assessment)
 *
 * Public showcase for the Quantum Readiness Assessment Engine™ (the dashboard module
 * at /dashboard/quantum-readiness). Light theme matching QGuard Messaging: white +
 * dot-grid background, CyberBackground particle field, gold/cyan/violet accents,
 * GlassCard system, Framer Motion reveals.
 *
 * Copy and module set are derived from the live dashboard (KPIs + 8 assessment
 * modules). Console/score figures are an illustrative product preview, clearly
 * labelled — never presented as a tenant's live posture.
 */
import { motion } from 'motion/react';
import {
  Activity,
  AlertTriangle,
  ArrowRight,
  BrainCircuit,
  Boxes,
  Clock,
  Cpu,
  EyeOff,
  FileText,
  Gauge,
  KeyRound,
  LayoutDashboard,
  Network,
  Radar,
  Rocket,
  ScanSearch,
  ShieldAlert,
  ShieldCheck,
  Sparkles,
  Target,
  TrendingUp,
  type LucideIcon,
} from 'lucide-react';
import {
  QuantumReadinessLayout,
  Reveal,
  Highlight,
  Kicker,
  SectionHeading,
  GlassCard,
  FeatureCard,
  TrustStrip,
  DarkButton,
  GoldButton,
  GhostButton,
  CTASection,
  CountUp,
  ReadinessRing,
  ScoreCard,
  ModuleSpotlight,
  type Feature,
  type Score,
} from './_shared';

/* Score tones (aligned with the dashboard palette). */
const GREEN = '#22c55e';
const RED = '#ef4444';
const ORANGE = '#f97316';
const AMBER = '#f59e0b';
const CYAN = '#06b6d4';
const BLUE = '#3b82f6';
const VIOLET = '#8b5cf6';

const TRUST = ['NIST FIPS 203', 'FIPS 204', 'FIPS 205', 'Evidence-Driven', 'Real-Time Telemetry', 'Multi-Tenant'];

/* Illustrative preview figures — kept consistent between the hero console and the
   scoring section below. Not a live tenant posture. */
const DEMO = {
  readiness: 74,
  risk: 38,
  hndl: 52,
  pqcAdoption: 41,
  assets: 12480,
  vulnerable: 4860,
  keys: 3204,
  certs: 1190,
};

const SCORES: Score[] = [
  { label: 'Quantum Readiness', value: DEMO.readiness, suffix: '/100', detail: 'Composite posture score', color: GREEN, ring: DEMO.readiness, icon: ShieldCheck },
  { label: 'Quantum Risk', value: DEMO.risk, suffix: '/100', detail: 'Weighted exposure index', color: ORANGE, ring: DEMO.risk, icon: ShieldAlert },
  { label: 'HNDL Risk', value: DEMO.hndl, suffix: '/100', detail: 'Harvest-now-decrypt-later', color: AMBER, ring: DEMO.hndl, icon: Target },
  { label: 'PQC Adoption', value: DEMO.pqcAdoption, suffix: '%', detail: 'Assets already quantum-safe', color: CYAN, ring: DEMO.pqcAdoption, icon: Gauge },
  { label: 'Assets Assessed', value: DEMO.assets, detail: `${DEMO.vulnerable.toLocaleString()} quantum-vulnerable`, color: BLUE, icon: Boxes },
  { label: 'Keys Discovered', value: DEMO.keys, detail: `+ ${DEMO.certs.toLocaleString()} certificates analyzed`, color: VIOLET, icon: KeyRound },
];

const LIFECYCLE: Array<{ icon: LucideIcon; name: string; body: string; color: string }> = [
  { icon: ScanSearch, name: 'Discover', body: 'Inventory every key, certificate and algorithm across cloud, on-prem and SaaS.', color: BLUE },
  { icon: Gauge, name: 'Assess', body: 'Score quantum readiness, risk and HNDL exposure from real evidence.', color: CYAN },
  { icon: BrainCircuit, name: 'Plan', body: 'Generate AI migration waves with sequencing and rollback paths.', color: VIOLET },
  { icon: Rocket, name: 'Migrate', body: 'Execute PQC changes with validation checkpoints and guardrails.', color: ORANGE },
  { icon: ShieldCheck, name: 'Validate', body: 'Confirm each asset is genuinely PQC-ready — no false positives.', color: GREEN },
  { icon: Activity, name: 'Monitor', body: 'Continuously watch posture and drift, long after cutover.', color: AMBER },
];

const MODULE_GRID: Feature[] = [
  { icon: TrendingUp, title: 'Executive Dashboard', body: 'Board-ready posture, business impact and forecast — the story your CISO can take upstairs.' },
  { icon: Network, title: 'Quantum Exposure Graph™', body: 'Interactive dependency and blast-radius map showing exactly what breaks when an algorithm falls.' },
  { icon: ShieldAlert, title: 'Quantum Risk Analysis', body: 'Technical risk prioritization with the evidence behind every score — algorithm, asset and severity.' },
  { icon: Sparkles, title: 'AI Executive Advisor™', body: 'Evidence-grounded advisory that translates cryptography into decisions, timelines and dollars.' },
  { icon: FileText, title: 'Report Center', body: 'Customer-facing reports and audit-ready evidence packages, generated on demand.' },
];

const STANDARDS: Array<{ purpose: string; algo: string; standard: string }> = [
  { purpose: 'Key establishment', algo: 'ML-KEM (512 / 768 / 1024)', standard: 'FIPS 203' },
  { purpose: 'Digital signatures', algo: 'ML-DSA', standard: 'FIPS 204' },
  { purpose: 'Stateless hash signatures', algo: 'SLH-DSA', standard: 'FIPS 205' },
  { purpose: 'Symmetric / AEAD', algo: 'AES-256-GCM', standard: 'FIPS 197' },
  { purpose: 'Hashing', algo: 'SHA3-256 / SHA3-512', standard: 'FIPS 202' },
];

/* Hero console mini-tile. */
function ConsoleTile({ icon: Icon, label, value, tone }: { icon: LucideIcon; label: string; value: string; tone: string }) {
  return (
    <div className="rounded-xl border border-white/10 bg-white/[0.04] p-4">
      <Icon className="h-5 w-5" style={{ color: tone }} />
      <div className="mt-2 font-mono text-[10px] uppercase tracking-widest text-slate-400">{label}</div>
      <div className="font-mono text-sm font-bold text-white">{value}</div>
    </div>
  );
}

export default function QuantumReadinessAssessmentPage() {
  return (
    <QuantumReadinessLayout>
      <span id="top" />

      {/* ---------------------------------------------------------------- Hero -- */}
      <section className="relative px-6 pb-16 pt-28 sm:pt-32">
        <div className="mx-auto grid max-w-[88rem] items-center gap-12 lg:grid-cols-[1.05fr_0.95fr]">
          <Reveal>
            <Kicker>Quantum Readiness Assessment Engine™</Kicker>
            <h1 className="mt-5 text-4xl font-black leading-[1.05] tracking-tight text-slate-900 sm:text-6xl">
              Measure your <Highlight>quantum risk</Highlight>.<br />Prove your <Highlight>readiness</Highlight>.
            </h1>
            <p className="mt-5 max-w-xl text-base leading-relaxed text-slate-600 sm:text-lg">
              The Quantum Readiness Assessment Engine turns cryptographic inventory, runtime telemetry and trust
              intelligence into a single board-ready readiness score — with AI advisory, blast-radius mapping and
              migration planning behind every number.
            </p>
            <div className="mt-8 flex flex-wrap items-center gap-3">
              <GoldButton href="/login">Launch the App</GoldButton>
              <DarkButton to="/dashboard/quantum-readiness">View Live Dashboard</DarkButton>
            </div>
            <div className="mt-8">
              <TrustStrip items={TRUST} />
            </div>
          </Reveal>

          {/* Signature: live "Quantum Readiness Console" preview panel. */}
          <Reveal delay={0.15}>
            {/* Colours here use explicit slate/cyan (not text-white / gold) so the
                light-theme override sheet leaves this dark instrument panel intact. */}
            <div className="relative overflow-hidden rounded-2xl border-2 border-slate-900 bg-[#040810] p-6 text-slate-200 shadow-[0_30px_90px_rgba(2,6,23,0.35)]">
              <div className="absolute inset-x-0 top-0 h-[3px] bg-gradient-to-r from-cyan-400 via-sky-500 to-violet-500" />
              <div className="flex items-center justify-between">
                <span className="font-mono text-[10px] font-bold uppercase tracking-widest text-slate-400">QUANTUM_READINESS // LIVE PREVIEW</span>
                <span className="inline-flex items-center gap-1.5 font-mono text-[10px] font-bold text-emerald-400">
                  <span className="h-1.5 w-1.5 animate-pulse rounded-full bg-emerald-400" /> ASSESSING
                </span>
              </div>

              <div className="mt-6 flex items-center gap-6">
                <ReadinessRing value={DEMO.readiness} color={GREEN} size={140} stroke={12}>
                  <div>
                    <div className="text-3xl font-black text-slate-50">
                      <CountUp value={DEMO.readiness} />
                    </div>
                    <div className="font-mono text-[9px] font-bold uppercase tracking-widest text-slate-400">Readiness</div>
                  </div>
                </ReadinessRing>
                <div className="min-w-0 flex-1 space-y-3">
                  <div>
                    <div className="font-mono text-[9px] font-bold uppercase tracking-widest text-slate-500">Readiness Level</div>
                    <div className="text-lg font-bold text-emerald-400">Advancing</div>
                  </div>
                  <div className="grid grid-cols-2 gap-3">
                    <div>
                      <div className="font-mono text-[9px] font-bold uppercase tracking-widest text-slate-500">Critical</div>
                      <div className="font-mono text-lg text-rose-400">27</div>
                    </div>
                    <div>
                      <div className="font-mono text-[9px] font-bold uppercase tracking-widest text-slate-500">Findings</div>
                      <div className="font-mono text-lg text-slate-200">1,842</div>
                    </div>
                  </div>
                </div>
              </div>

              <div className="mt-6 grid grid-cols-2 gap-3">
                <ConsoleTile icon={ShieldAlert} label="Quantum Risk" value={`${DEMO.risk}/100`} tone="#fb923c" />
                <ConsoleTile icon={Target} label="HNDL Risk" value={`${DEMO.hndl}/100`} tone="#fbbf24" />
                <ConsoleTile icon={Boxes} label="Assets" value={DEMO.assets.toLocaleString()} tone="#60a5fa" />
                <ConsoleTile icon={KeyRound} label="Keys" value={DEMO.keys.toLocaleString()} tone="#a78bfa" />
              </div>

              <div className="mt-5 flex items-center justify-between rounded-xl border border-cyan-400/25 bg-cyan-400/10 px-4 py-3">
                <span className="font-mono text-[10px] font-bold uppercase tracking-widest text-cyan-200">Evidence-Grounded Scoring</span>
                <ShieldCheck className="h-4 w-4 text-cyan-300" />
              </div>
            </div>
          </Reveal>
        </div>
      </section>

      {/* ---------------------------------------------------- The quantum threat -- */}
      <section className="mx-auto max-w-[88rem] px-6 py-12">
        <Reveal>
          <GlassCard className="grid items-center gap-8 overflow-hidden p-6 sm:p-8 lg:grid-cols-2" hover={false}>
            <div>
              <span className="inline-flex items-center gap-2 rounded-full border border-rose-300/60 bg-rose-50 px-3 py-1 font-mono text-[11px] font-bold uppercase tracking-[0.2em] text-rose-600">
                <Clock className="h-3.5 w-3.5" /> The deadline is already here
              </span>
              <h2 className="mt-4 text-3xl font-black tracking-tight text-slate-900 sm:text-4xl">
                &ldquo;Harvest now, decrypt later&rdquo; isn&rsquo;t a <Highlight>someday</Highlight> problem.
              </h2>
              <p className="mt-3 text-base leading-relaxed text-slate-600">
                Adversaries are already recording encrypted traffic to decrypt once a cryptographically-relevant quantum
                computer arrives. Anything that must stay secret for a decade is exposed <em>today</em>. You can&rsquo;t
                fix what you can&rsquo;t see — the first step is knowing exactly where RSA and ECC still live.
              </p>
              <div className="mt-6 grid grid-cols-3 gap-3">
                {[
                  { k: '2030', v: 'RSA & ECC deprecated (NIST)' },
                  { k: '2035', v: 'Legacy crypto disallowed' },
                  { k: '10+ yr', v: 'Secrets already at risk' },
                ].map((s) => (
                  <div key={s.k} className="rounded-xl border border-slate-200 bg-white/70 p-3 text-center">
                    <div className="text-xl font-black text-slate-900">{s.k}</div>
                    <div className="mt-1 text-[11px] leading-tight text-slate-500">{s.v}</div>
                  </div>
                ))}
              </div>
            </div>
            <motion.div
              whileHover={{ scale: 1.02 }}
              transition={{ duration: 0.4 }}
              className="relative overflow-hidden rounded-xl border border-slate-200 bg-slate-950 shadow-[0_24px_70px_rgba(2,6,23,0.25)]"
            >
              <div className="absolute inset-x-0 top-0 z-10 h-[3px] bg-gradient-to-r from-rose-500 via-gold to-cyan-400" />
              <img src="/Breaking_RSA_ECC.png" alt="Quantum computers breaking RSA and ECC" className="h-full max-h-[320px] w-full object-cover opacity-95" />
            </motion.div>
          </GlassCard>
        </Reveal>
      </section>

      {/* ----------------------------------------------------------- Lifecycle -- */}
      <section className="mx-auto max-w-[88rem] px-6 py-14">
        <SectionHeading
          kicker="The Assessment Lifecycle"
          title={<>From first scan to <Highlight>continuous assurance</Highlight></>}
          subtitle="Every module maps to one stage of the quantum-safe journey — a single, evidence-driven loop from discovery through ongoing monitoring."
        />
        <div className="mt-12 grid grid-cols-2 gap-4 md:grid-cols-3 xl:grid-cols-6">
          {LIFECYCLE.map((stage, i) => {
            const Icon = stage.icon;
            return (
              <Reveal key={stage.name} delay={(i % 6) * 0.06} className="h-full">
                <GlassCard className="group relative h-full p-5">
                  <span className="font-mono text-[11px] font-black tracking-widest text-slate-300">{String(i + 1).padStart(2, '0')}</span>
                  <span
                    className="mt-3 flex h-11 w-11 items-center justify-center rounded-xl border transition-transform duration-300 group-hover:scale-110"
                    style={{ borderColor: `${stage.color}33`, color: stage.color, backgroundColor: `${stage.color}12` }}
                  >
                    <Icon className="h-5 w-5" />
                  </span>
                  <h3 className="mt-3 text-base font-black text-slate-900">{stage.name}</h3>
                  <p className="mt-1.5 text-xs leading-relaxed text-slate-600">{stage.body}</p>
                  {i < LIFECYCLE.length - 1 && (
                    <ArrowRight className="absolute right-3 top-5 hidden h-4 w-4 text-slate-300 xl:block" />
                  )}
                </GlassCard>
              </Reveal>
            );
          })}
        </div>
      </section>

      {/* ------------------------------------------------------------- Scoring -- */}
      <section id="scoring" className="mx-auto max-w-[88rem] scroll-mt-24 px-6 py-14">
        <SectionHeading
          kicker="Board-Ready Scoring"
          title={<>One score for the boardroom.<br /><Highlight>Full evidence</Highlight> for engineers.</>}
          subtitle="Six live indicators roll thousands of findings into numbers a CISO can act on — each traceable back to the exact key, certificate or algorithm behind it."
        />
        <div className="mt-12 grid grid-cols-1 gap-4 sm:grid-cols-2 xl:grid-cols-3">
          {SCORES.map((score, i) => (
            <ScoreCard key={score.label} score={score} delay={(i % 3) * 0.06} />
          ))}
        </div>
        <p className="mx-auto mt-6 max-w-2xl text-center text-xs leading-relaxed text-slate-500">
          Figures shown are an illustrative product preview. In production every score derives from your real scans,
          telemetry and inventory — never fabricated.
        </p>
      </section>

      {/* ------------------------------------------------------------- Modules -- */}
      <section id="modules" className="mx-auto max-w-[88rem] scroll-mt-24 px-6 py-14">
        <SectionHeading
          kicker="Inside the Engine"
          title={<>Eight modules. One <Highlight>quantum readiness</Highlight> picture.</>}
          subtitle="Discovery, scoring, AI advisory and HNDL threat intelligence — unified in a single assessment layer that the whole organization can read."
        />

        <div className="mt-12 space-y-8">
          <ModuleSpotlight
            icon={LayoutDashboard}
            eyebrow="Command Center"
            title="Run the assessment like a mission"
            blurb="A live operational cockpit for your quantum-readiness program — assessment progress, telemetry health, critical findings and recommended actions in one continuously updating view."
            bullets={[
              'Real-time assessment progress and coverage',
              'Live cryptographic telemetry with SSE health',
              'Prioritized critical-findings feed',
              'One click into every deep-dive module',
            ]}
            image="/monitoring.png"
          />
          <ModuleSpotlight
            icon={BrainCircuit}
            eyebrow="AI Migration Advisor™"
            title="A migration plan that sequences itself"
            blurb="Evidence-grounded AI turns your findings into ordered migration waves — with dependencies, effort, rollback paths and business impact scored for every move."
            bullets={[
              'Wave-based sequencing by risk and dependency',
              'Built-in rollback and validation checkpoints',
              'Effort, cost and impact estimates per wave',
              'Grounded in your real inventory — no guesswork',
            ]}
            image="/Reports/quantum-readiness-migration-planner.png"
            reverse
          />
          <ModuleSpotlight
            icon={EyeOff}
            eyebrow="Harvest Now, Decrypt Later"
            title="Find the data adversaries are already harvesting"
            blurb="A quantum threat operations center for harvest-now-decrypt-later risk — long-lived sensitive data, exposure windows and the assets whose encrypted traffic is worth stealing today."
            bullets={[
              'HNDL risk scoring from real inventory evidence',
              'Exposure-window analysis against data lifetime',
              'Internet-facing and high-value asset targeting view',
              'Prioritized mitigations for the riskiest flows',
            ]}
            image="/HarvestNow.png"
          />
        </div>

        <div className="mt-8 grid gap-5 sm:grid-cols-2 xl:grid-cols-3">
          {MODULE_GRID.map((f, i) => (
            <FeatureCard key={f.title} feature={f} delay={(i % 3) * 0.06} />
          ))}
        </div>
      </section>

      {/* ------------------------------------------------------------ AI-native -- */}
      <section className="mx-auto max-w-[88rem] px-6 py-8">
        <Reveal>
          <GlassCard className="relative overflow-hidden p-8 sm:p-10" hover={false}>
            <div className="pointer-events-none absolute -right-16 -top-16 h-56 w-56 rounded-full bg-violet-300/25 blur-[80px]" />
            <div className="pointer-events-none absolute -bottom-16 -left-16 h-56 w-56 rounded-full bg-cyan-300/25 blur-[80px]" />
            <div className="relative z-10 grid items-center gap-8 lg:grid-cols-[1.4fr_1fr]">
              <div>
                <span className="inline-flex items-center gap-2 rounded-full border border-violet-300/60 bg-violet-50 px-3 py-1 font-mono text-[11px] font-bold uppercase tracking-[0.2em] text-violet-600">
                  <Sparkles className="h-3.5 w-3.5" /> AI-native, evidence-grounded
                </span>
                <h2 className="mt-4 text-2xl font-black tracking-tight text-slate-900 sm:text-3xl">
                  Advice you can defend in an audit
                </h2>
                <p className="mt-3 text-sm leading-relaxed text-slate-600">
                  Every AI recommendation cites the findings, assets and standards it was built from. No black boxes,
                  no hallucinated posture — just traceable reasoning your executives and auditors can follow line by line.
                </p>
                <div className="mt-5 flex flex-wrap gap-3">
                  <DarkButton to="/dashboard/quantum-readiness/ai-executive-advisor">AI Executive Advisor</DarkButton>
                  <GhostButton to="/dashboard/quantum-readiness/ai-migration-advisor">AI Migration Advisor</GhostButton>
                </div>
              </div>
              <div className="grid grid-cols-3 gap-3">
                {[
                  { icon: Radar, k: 'Traceable', tone: CYAN },
                  { icon: Cpu, k: 'Grounded', tone: VIOLET },
                  { icon: AlertTriangle, k: 'Prioritized', tone: ORANGE },
                ].map((c) => (
                  <div key={c.k} className="rounded-xl border border-slate-200 bg-white/70 p-4 text-center">
                    <c.icon className="mx-auto h-6 w-6" style={{ color: c.tone }} />
                    <div className="mt-2 text-[11px] font-bold uppercase tracking-wide text-slate-700">{c.k}</div>
                  </div>
                ))}
              </div>
            </div>
          </GlassCard>
        </Reveal>
      </section>

      {/* ----------------------------------------------------------- Standards -- */}
      <section id="standards" className="mx-auto max-w-[88rem] scroll-mt-24 px-6 py-14">
        <SectionHeading
          kicker="Standards We Measure Against"
          title={<>Scored against the <Highlight>NIST</Highlight> post-quantum standards</>}
          subtitle="Readiness isn't an opinion. Every asset is graded against the finalized NIST algorithms — so a PQC-ready badge actually means something."
        />
        <div className="mt-10">
          <Reveal>
            <GlassCard className="overflow-hidden" hover={false}>
              <div className="grid grid-cols-1 divide-y divide-slate-200 sm:grid-cols-2 sm:divide-x lg:grid-cols-5 lg:divide-y-0">
                {STANDARDS.map((row) => (
                  <div key={row.purpose} className="p-5">
                    <div className="font-mono text-[10px] font-bold uppercase tracking-widest text-slate-500">{row.purpose}</div>
                    <div className="mt-2 font-mono text-sm font-bold text-slate-900">{row.algo}</div>
                    <div className="mt-2 inline-flex rounded-full border border-gold/30 bg-gold/10 px-2 py-0.5 font-mono text-[10px] font-bold text-[#b8860b]">{row.standard}</div>
                  </div>
                ))}
              </div>
            </GlassCard>
          </Reveal>
        </div>
        <p className="mx-auto mt-4 max-w-2xl text-center text-xs leading-relaxed text-slate-500">
          Hybrid deployments (X25519 + ML-KEM, Ed25519 + ML-DSA) are recognized and scored as first-class quantum-safe posture.
        </p>
      </section>

      {/* ----------------------------------------------------------------- CTA -- */}
      <CTASection
        title="See your quantum readiness score"
        body="Run a discovery scan and watch inventory, telemetry and trust intelligence resolve into a single readiness number — with the evidence and migration plan behind it."
        primary={{ label: 'Launch the App', href: '/login' }}
        secondary={{ label: 'View Live Dashboard', to: '/dashboard/quantum-readiness' }}
      />
    </QuantumReadinessLayout>
  );
}
