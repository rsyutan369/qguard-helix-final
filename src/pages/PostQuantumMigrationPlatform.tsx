/**
 * Post-Quantum Migration Platform — marketing overview (/post-quantum-migration-platform)
 *
 * Public "Learn More" page for the PRO product. Reuses the exact QGuard Messaging
 * + Quantum Readiness Assessment design language (light theme, GlassCard system,
 * gold/cyan/violet accents, Framer Motion reveals) via the shared SolutionLayout.
 *
 * Copy and modules derive from the Pro tier capabilities on the pricing page.
 * Console figures are an illustrative product preview — never a live tenant posture.
 */
import { motion } from 'motion/react';
import {
  Activity,
  ArrowRight,
  Boxes,
  Clock,
  Cpu,
  Database,
  Fingerprint,
  Gauge,
  GitBranch,
  Layers,
  Network,
  Radar,
  RefreshCcw,
  Rocket,
  ScanSearch,
  Share2,
  ShieldAlert,
  ShieldCheck,
  Target,
  Zap,
  type LucideIcon,
} from 'lucide-react';
import {
  SolutionLayout,
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
  ModuleSpotlight,
  ConsoleTile,
  ConsoleMeter,
  type Feature,
} from './_solution-shared';

const CYAN = '#06b6d4';
const BLUE = '#3b82f6';
const VIOLET = '#8b5cf6';
const GREEN = '#22c55e';
const AMBER = '#f59e0b';
const ORANGE = '#f97316';

const NAV_LINKS = [
  { label: 'Overview', href: '#top' },
  { label: 'Lifecycle', href: '#lifecycle' },
  { label: 'Capabilities', href: '#capabilities' },
  { label: 'Included', href: '#included' },
];

const TRUST = ['Up to 500 Assets', 'Assets & CBOM', 'Rollback-Safe', 'Runtime Telemetry', 'HNDL Defense', 'Crypto-Agility'];

const LIFECYCLE: Array<{ icon: LucideIcon; name: string; body: string; color: string }> = [
  { icon: ScanSearch, name: 'Discover', body: 'Scan cloud, on-prem and SaaS to inventory every key, certificate and algorithm in use.', color: BLUE },
  { icon: Network, name: 'Map', body: 'Build the CBOM and trust-chain graph — see what depends on what before you move.', color: CYAN },
  { icon: Layers, name: 'Plan', body: 'Sequence migration into waves by risk, dependency and effort, with a sandbox to model each.', color: VIOLET },
  { icon: RefreshCcw, name: 'Orchestrate', body: 'Roll out PQC and hybrid changes with live ops, guardrails and validation checkpoints.', color: ORANGE },
  { icon: ShieldCheck, name: 'Cutover', body: 'Execute rollback-safe cutovers — every change reversible if a check fails.', color: GREEN },
  { icon: Activity, name: 'Monitor', body: 'Watch runtime crypto and drift continuously, long after the migration lands.', color: AMBER },
];

const SPOTLIGHTS: Array<{
  icon: LucideIcon;
  eyebrow: string;
  title: string;
  blurb: string;
  bullets: string[];
  image: string;
  reverse?: boolean;
}> = [
  {
    icon: Database,
    eyebrow: 'Cryptographic Asset Management',
    title: 'A living inventory of your entire crypto estate',
    blurb: 'Scan, discover and monitor up to 500 cryptographic assets, then explore them in the Assets & CBOM Explorer — certificates, keys and algorithms, with ownership and risk on every one.',
    bullets: [
      'Continuous discovery across cloud, on-prem and SaaS',
      'CBOM inventory with ownership and dependency mapping',
      'Quantum-risk scoring on every asset',
      'Up to 500 monitored assets',
    ],
    image: '/inventory.png',
  },
  {
    icon: RefreshCcw,
    eyebrow: 'Migration Planner, Timeline & Sandbox',
    title: 'A migration plan you can rehearse before you run it',
    blurb: 'Plan the whole program on a timeline, then model each wave in a sandbox to see the readiness lift, blast radius and compatibility risk — before a single key rotates in production.',
    bullets: [
      'Wave-based sequencing by risk and dependency',
      'Sandbox simulation with zero production risk',
      'Timeline view of the full migration program',
      'Effort and impact estimates per wave',
    ],
    image: '/Migration_Planner.png',
    reverse: true,
  },
  {
    icon: Rocket,
    eyebrow: 'PQC Orchestration, Live Ops & Rollback',
    title: 'Execute the cutover with a safety net',
    blurb: 'Orchestrate PQC and hybrid rollouts with live migration operations, validation checkpoints and one-click rollback — so a failed check never becomes a production incident.',
    bullets: [
      'Guided orchestration of PQC and hybrid changes',
      'Live migration ops with real-time status',
      'Validation checkpoints at every gate',
      'One-click, rollback-safe cutovers',
    ],
    image: '/migration_wizard.png',
  },
  {
    icon: Activity,
    eyebrow: 'Runtime & Cryptographic Intelligence',
    title: 'See the cryptography your systems actually use',
    blurb: 'Runtime telemetry shows the algorithms your applications negotiate in production as they run — not what a config file claims — so you catch shadow crypto and drift the moment it appears.',
    bullets: [
      'Live runtime cryptographic telemetry',
      'Shadow-crypto and drift detection',
      'Protocol, TLS and certificate visibility',
      'Evidence you can trace to a real observation',
    ],
    image: '/monitoring.png',
    reverse: true,
  },
];

const FEATURE_GRID: Feature[] = [
  { icon: Network, title: 'Supply Chain Readiness Center', body: 'Assess third-party and vendor PQC readiness, and map the blast radius of a weak link across your ecosystem.' },
  { icon: ShieldAlert, title: 'Harvest Now, Decrypt Later Center', body: 'Find and prioritize the long-lived secrets an adversary could record today and decrypt after Q-Day.' },
  { icon: Share2, title: 'Trust Chain Analysis', body: 'Trace certificate and key trust chains end to end — and see exactly what breaks when an algorithm falls.' },
  { icon: Zap, title: 'Crypto-Agility Engine', body: 'Make cryptography swappable — adopt hybrid PQC and pivot algorithms without re-architecting systems.' },
  { icon: Fingerprint, title: 'PQC-Auth Identity Migration', body: 'Modernize OAuth/OIDC, tokens and machine identities onto quantum-safe signatures.' },
  { icon: Gauge, title: 'Live Migration Ops', body: 'A real-time operations view of every in-flight change, checkpoint and rollback across the program.' },
];

const INCLUDED = [
  'Everything in Starter and Basic',
  'Scan, Discover and Monitor up to 500 crypto assets',
  'Assets and CBOM Explorer',
  'Migration Planner, Timeline and Sandbox Analysis',
  'PQC-Auth Identity Migration Engine',
  'PQC orchestration, Live Migration ops, Rollback',
  'Runtime & Cryptographic Intelligence',
  'Supply Chain Readiness Center',
  'Harvest Now, Decrypt Later Center',
  'Trust Chain Analysis',
  'Crypto Agility Engine',
  'Email Support',
];

const FOOTER_GROUPS = [
  {
    title: 'Solutions',
    links: [
      { label: 'Qguard Messaging', to: '/qguard-messaging' },
      { label: 'Quantum Readiness', to: '/quantum-readiness-assessment' },
      { label: 'Free Scan', to: '/public-scan' },
      { label: 'Migration Platform', to: '/post-quantum-migration-platform' },
      { label: 'Trust & Governance', to: '/quantum-trust-governance-center' },
    ],
  },
  {
    title: 'Platform',
    links: [
      { label: 'QGuard Helix', href: '/' },
      { label: 'Pricing', href: '/#pricing' },
      { label: 'Documentation', href: '/docs' },
      { label: 'Live Dashboard', href: '/dashboard/migration-planner' },
    ],
  },
  {
    title: 'Company',
    links: [
      { label: 'Sign in', href: '/login' },
      { label: 'Get started', href: '/register' },
      { label: 'Contact', href: '/docs' },
    ],
  },
];

export default function PostQuantumMigrationPlatform() {
  return (
    <SolutionLayout
      homePath="/post-quantum-migration-platform"
      brandTitle="Migration Platform"
      brandSubtitle="Post-Quantum Operations"
      brandTagline="Post-Quantum Migration"
      navLinks={NAV_LINKS}
      footerBlurb="The operational core of your post-quantum transition — discover the crypto estate, then plan, orchestrate and validate the migration to PQC with rollback-safe controls and runtime intelligence."
      footerGroups={FOOTER_GROUPS}
    >
      <span id="top" />

      {/* ------------------------------------------------------------------ Hero -- */}
      <section className="relative px-6 pb-16 pt-28 sm:pt-32">
        <div className="mx-auto grid max-w-[88rem] items-center gap-12 lg:grid-cols-[1.05fr_0.95fr]">
          <Reveal>
            <Kicker>Post-Quantum Migration Platform</Kicker>
            <h1 className="mt-5 text-4xl font-black leading-[1.05] tracking-tight text-slate-900 sm:text-6xl">
              See every asset.<br />
              <Highlight>Migrate</Highlight> with confidence.
            </h1>
            <p className="mt-5 max-w-xl text-base leading-relaxed text-slate-600 sm:text-lg">
              Discover your entire cryptographic estate, then plan, execute and monitor the migration to
              post-quantum cryptography — with runtime intelligence, supply-chain visibility and
              rollback-safe controls behind every change.
            </p>
            <div className="mt-8 flex flex-wrap items-center gap-3">
              <GoldButton to="/checkout?plan=Pro&cycle=yearly">Choose Pro</GoldButton>
              <DarkButton href="/#pricing">Compare Plans</DarkButton>
            </div>
            <div className="mt-8">
              <TrustStrip items={TRUST} />
            </div>
          </Reveal>

          {/* Signature: dark "Migration Command" console. Explicit slate/cyan
              colours keep it intact under the light-theme override sheet. */}
          <Reveal delay={0.15}>
            <div className="relative overflow-hidden rounded-2xl border-2 border-slate-900 bg-[#040810] p-6 text-slate-200 shadow-[0_30px_90px_rgba(2,6,23,0.35)]">
              <div className="absolute inset-x-0 top-0 h-[3px] bg-gradient-to-r from-cyan-400 via-sky-500 to-violet-500" />
              <div className="flex items-center justify-between">
                <span className="font-mono text-[10px] font-bold uppercase tracking-widest text-slate-400">MIGRATION_OPS // LIVE PREVIEW</span>
                <span className="inline-flex items-center gap-1.5 font-mono text-[10px] font-bold text-emerald-400">
                  <span className="h-1.5 w-1.5 animate-pulse rounded-full bg-emerald-400" /> MIGRATING
                </span>
              </div>

              <div className="mt-6 flex items-center gap-6">
                <ReadinessRing value={62} color={CYAN} size={140} stroke={12}>
                  <div>
                    <div className="text-3xl font-black text-slate-50">
                      <CountUp value={62} suffix="%" />
                    </div>
                    <div className="font-mono text-[9px] font-bold uppercase tracking-widest text-slate-400">Migrated</div>
                  </div>
                </ReadinessRing>
                <div className="min-w-0 flex-1 space-y-2.5">
                  <ConsoleMeter label="Discover" value={100} color={BLUE} />
                  <ConsoleMeter label="Plan" value={84} color={VIOLET} />
                  <ConsoleMeter label="Orchestrate" value={57} color={ORANGE} />
                  <ConsoleMeter label="Validate" value={41} color={GREEN} />
                </div>
              </div>

              <div className="mt-6 grid grid-cols-2 gap-3">
                <ConsoleTile icon={Boxes} label="Assets" value="500" tone="#60a5fa" />
                <ConsoleTile icon={Layers} label="Migration Waves" value="8" tone="#a78bfa" />
                <ConsoleTile icon={Activity} label="Live Ops" value="Active" tone="#34d399" />
                <ConsoleTile icon={RefreshCcw} label="Rollback" value="Ready" tone="#fbbf24" />
              </div>

              <div className="mt-5 flex items-center justify-between rounded-xl border border-cyan-400/25 bg-cyan-400/10 px-4 py-3">
                <span className="font-mono text-[10px] font-bold uppercase tracking-widest text-cyan-200">Rollback-Safe Cutovers</span>
                <ShieldCheck className="h-4 w-4 text-cyan-300" />
              </div>
            </div>
          </Reveal>
        </div>
      </section>

      {/* --------------------------------------------------- You can't migrate... -- */}
      <section className="mx-auto max-w-[88rem] px-6 py-12">
        <Reveal>
          <GlassCard className="grid items-center gap-8 overflow-hidden p-6 sm:p-8 lg:grid-cols-2" hover={false}>
            <div>
              <span className="inline-flex items-center gap-2 rounded-full border border-rose-300/60 bg-rose-50 px-3 py-1 font-mono text-[11px] font-bold uppercase tracking-[0.2em] text-rose-600">
                <Clock className="h-3.5 w-3.5" /> The clock is already running
              </span>
              <h2 className="mt-4 text-3xl font-black tracking-tight text-slate-900 sm:text-4xl">
                You can&rsquo;t migrate what you can&rsquo;t <Highlight>see</Highlight>.
              </h2>
              <p className="mt-3 text-base leading-relaxed text-slate-600">
                Most organizations don&rsquo;t know where RSA and ECC still live — in code, certificates, tokens
                and third-party services. A migration that starts with a spreadsheet stalls. The Migration Platform
                starts with a live inventory, then turns it into a sequenced, rollback-safe program you can actually run.
              </p>
              <div className="mt-6 grid grid-cols-3 gap-3">
                {[
                  { k: '500', v: 'Assets discovered & monitored' },
                  { k: '8 waves', v: 'Sequenced by risk & dependency' },
                  { k: '0', v: 'Production risk in the sandbox' },
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
              <div className="absolute inset-x-0 top-0 z-10 h-[3px] bg-gradient-to-r from-cyan-400 via-gold to-violet-500" />
              <img src="/visibility.png" alt="Cryptographic asset visibility across the estate" className="h-full max-h-[320px] w-full object-cover opacity-95" />
            </motion.div>
          </GlassCard>
        </Reveal>
      </section>

      {/* ------------------------------------------------------------- Lifecycle -- */}
      <section id="lifecycle" className="mx-auto max-w-[88rem] scroll-mt-24 px-6 py-14">
        <SectionHeading
          kicker="The Migration Lifecycle"
          title={<>From first scan to <Highlight>rollback-safe cutover</Highlight></>}
          subtitle="One operational loop — discover the estate, map dependencies, sequence the waves, orchestrate the change, and keep watching after it lands."
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

      {/* ---------------------------------------------------------- Spotlights -- */}
      <section id="capabilities" className="mx-auto max-w-[88rem] scroll-mt-24 px-6 py-14">
        <SectionHeading
          kicker="Inside the Platform"
          title={<>Discover, plan, orchestrate &mdash; <Highlight>one platform</Highlight></>}
          subtitle="The operational core of the QGuard Helix migration program, unified so security, platform and identity teams work from the same live picture."
        />
        <div className="mt-12 space-y-8">
          {SPOTLIGHTS.map((s) => (
            <div key={s.title}>
              <ModuleSpotlight
                icon={s.icon}
                eyebrow={s.eyebrow}
                title={s.title}
                blurb={s.blurb}
                bullets={s.bullets}
                image={s.image}
                reverse={s.reverse}
              />
            </div>
          ))}
        </div>

        <div className="mt-8 grid gap-5 sm:grid-cols-2 xl:grid-cols-3">
          {FEATURE_GRID.map((f, i) => (
            <FeatureCard key={f.title} feature={f} delay={(i % 3) * 0.06} />
          ))}
        </div>
      </section>

      {/* ------------------------------------------------------------ AI-native -- */}
      <section className="mx-auto max-w-[88rem] px-6 py-8">
        <Reveal>
          <GlassCard className="relative overflow-hidden p-8 sm:p-10" hover={false}>
            <div className="pointer-events-none absolute -right-16 -top-16 h-56 w-56 rounded-full bg-cyan-300/25 blur-[80px]" />
            <div className="pointer-events-none absolute -bottom-16 -left-16 h-56 w-56 rounded-full bg-violet-300/25 blur-[80px]" />
            <div className="relative z-10 grid items-center gap-8 lg:grid-cols-[1.4fr_1fr]">
              <div>
                <span className="inline-flex items-center gap-2 rounded-full border border-cyan-300/60 bg-cyan-50 px-3 py-1 font-mono text-[11px] font-bold uppercase tracking-[0.2em] text-cyan-700">
                  <Radar className="h-3.5 w-3.5" /> Evidence-grounded operations
                </span>
                <h2 className="mt-4 text-2xl font-black tracking-tight text-slate-900 sm:text-3xl">
                  Every move traces back to a real observation
                </h2>
                <p className="mt-3 text-sm leading-relaxed text-slate-600">
                  The platform builds each migration wave from your actual inventory and runtime telemetry — not
                  assumptions. So the plan an engineer executes and the story a CISO tells upstairs are the same
                  evidence, end to end.
                </p>
                <div className="mt-5 flex flex-wrap gap-3">
                  <DarkButton href="/#pricing">Choose Pro</DarkButton>
                  <GhostButton to="/quantum-trust-governance-center">Explore Elite Governance</GhostButton>
                </div>
              </div>
              <div className="grid grid-cols-3 gap-3">
                {[
                  { icon: Radar, k: 'Traceable', tone: CYAN },
                  { icon: Cpu, k: 'Grounded', tone: VIOLET },
                  { icon: Target, k: 'Prioritized', tone: ORANGE },
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

      {/* ------------------------------------------------------------- Included -- */}
      <section id="included" className="mx-auto max-w-[88rem] scroll-mt-24 px-6 py-14">
        <SectionHeading
          kicker="Everything in Pro"
          title={<>One plan for the whole <Highlight>migration program</Highlight></>}
          subtitle="Pro builds on Starter and Basic and adds the full discovery, migration and runtime operations suite."
        />
        <div className="mx-auto mt-10 max-w-4xl">
          <Reveal>
            <GlassCard className="p-8" hover={false}>
              <div className="flex flex-wrap items-baseline gap-x-2">
                <span className="font-mono text-4xl font-black text-slate-900">$30</span>
                <span className="font-mono text-sm text-slate-500">/mo</span>
                <span className="ml-2 rounded-full border border-gold/30 bg-gold/10 px-2 py-0.5 font-mono text-[10px] font-bold text-[#b8860b]">$20/mo billed yearly</span>
              </div>
              <ul className="mt-6 grid gap-3 sm:grid-cols-2">
                {INCLUDED.map((item) => (
                  <li key={item} className="flex items-start gap-2.5 text-sm text-slate-700">
                    <ShieldCheck className="mt-0.5 h-4 w-4 shrink-0 text-gold" />
                    <span>{item}</span>
                  </li>
                ))}
              </ul>
              <div className="mt-8 flex flex-wrap gap-3">
                <GoldButton to="/checkout?plan=Pro&cycle=yearly">Choose Pro</GoldButton>
                <GhostButton href="/#pricing">Compare all plans</GhostButton>
              </div>
            </GlassCard>
          </Reveal>
        </div>
      </section>

      {/* ----------------------------------------------------------------- CTA -- */}
      <CTASection
        title="Turn your crypto estate into a migration you can run"
        body="Discover every asset, sequence the waves, and execute rollback-safe cutovers — with runtime intelligence and evidence behind every move."
        primary={{ label: 'Choose Pro', to: '/checkout?plan=Pro&cycle=yearly' }}
        secondary={{ label: 'Compare Plans', href: '/#pricing' }}
      />
    </SolutionLayout>
  );
}
