/**
 * PQC Solutions — marketing overview (/pqc-solutions)
 *
 * Public page that maps the six real-world PQC problems from
 * Qguard_Wiki/Problems_To_Solve_1..6 to the QGuard Helix capabilities that
 * solve them (module mapping per Qguard_Wiki/Problem_Solution_Traceability.md).
 * Reuses the exact QGuard Messaging + Quantum Readiness Assessment design
 * language via the shared SolutionLayout; violet is the lead accent here so
 * the page reads as a sibling of the Pro (cyan) and Elite (gold) pages.
 *
 * Console figures are an illustrative product preview — never a live tenant posture.
 */
import React from 'react';
import { motion } from 'motion/react';
import {
  Activity,
  Archive,
  ArrowRight,
  Atom,
  CheckCircle2,
  ClipboardCheck,
  FlaskConical,
  Gauge,
  Handshake,
  KeyRound,
  Radar,
  Route,
  ScanSearch,
  Share2,
  ShieldAlert,
  Target,
  Timer,
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
  StepCard,
  ModuleSpotlight,
  type Feature,
} from './_solution-shared';

const VIOLET = '#8b5cf6';
const CYAN = '#06b6d4';
const EMERALD = '#10b981';
const AMBER = '#f59e0b';
const ROSE = '#f43f5e';

const NAV_LINKS = [
  { label: 'Overview', href: '#top' },
  { label: 'The Pattern', href: '#pattern' },
  { label: 'Six Problems', href: '#problems' },
  { label: 'Platform', href: '#platform' },
];

const TRUST = [
  'Trust-State Discovery',
  'Shor vs Grover Triage',
  'Trust Path Cost',
  'Shadow Crypto',
  'QKMS Key Lifecycle',
  'Rollback-Safe Migration',
];

/* ------------------------------------------------------------ Hero ledger -- */

const LEDGER: Array<{ problem: string; module: string }> = [
  { problem: 'Hidden trust hierarchies', module: 'Trust-State Discovery' },
  { problem: 'No trust inventory', module: '5-Checkpoint Migration Gate' },
  { problem: 'Trust as a runtime cost', module: 'TLS Trust Path Cost' },
  { problem: 'Shadow crypto & Shor/Grover', module: 'Scanner + Risk Scoring' },
  { problem: 'Unmanaged encryption keys', module: 'QKMS Lifecycle' },
  { problem: 'No enterprise roadmap', module: 'Planner + Sandbox' },
];

const LedgerRow: React.FC<{ index: number; problem: string; module: string }> = ({ index, problem, module }) => {
  return (
    <motion.div
      initial={{ opacity: 0, x: 14 }}
      animate={{ opacity: 1, x: 0 }}
      transition={{ duration: 0.45, delay: 0.35 + index * 0.12, ease: 'easeOut' }}
      className="flex items-center gap-3 rounded-lg border border-[#1e293b] bg-[#0b1322] px-3 py-2.5"
    >
      <span className="font-mono text-[10px] font-black tracking-widest text-slate-500">
        {String(index + 1).padStart(2, '0')}
      </span>
      <span className="min-w-0 flex-1 truncate text-xs font-semibold text-slate-200">{problem}</span>
      <ArrowRight className="h-3 w-3 shrink-0 text-slate-500" />
      <span className="hidden truncate font-mono text-[10px] font-bold uppercase tracking-wide text-violet-300 sm:block">
        {module}
      </span>
      <motion.span
        initial={{ scale: 0, opacity: 0 }}
        animate={{ scale: 1, opacity: 1 }}
        transition={{ duration: 0.3, delay: 0.65 + index * 0.12, type: 'spring', stiffness: 300 }}
      >
        <CheckCircle2 className="h-4 w-4 shrink-0 text-emerald-400" />
      </motion.span>
    </motion.div>
  );
};

/* -------------------------------------------------------- Pattern strip -- */

const PATTERN: Array<{ label: string; body: string; image: string; color: string }> = [
  {
    label: 'Visibility',
    body: 'Know what exists — every certificate, key, algorithm and endpoint.',
    image: '/visibility.png',
    color: CYAN,
  },
  {
    label: 'Ownership',
    body: 'Resolve who owns each asset before it blocks a migration wave.',
    image: '/ownership.png',
    color: EMERALD,
  },
  {
    label: 'Dependencies',
    body: 'Map what depends on what — including trust paths no inventory lists.',
    image: '/dependencies.png',
    color: VIOLET,
  },
  {
    label: 'Risk',
    body: 'Score operational and quantum risk on evidence, not assumptions.',
    image: '/risk.png',
    color: AMBER,
  },
  {
    label: 'Migration Gate',
    body: 'Proceed only when rollback and recovery paths are validated.',
    image: '/migration_gate.png',
    color: ROSE,
  },
];

const PatternCard: React.FC<{ stage: (typeof PATTERN)[number]; index: number }> = ({ stage, index }) => (
  <Reveal delay={index * 0.08} className="relative h-full">
    <GlassCard className="group h-full overflow-hidden p-0">
      <div className="relative h-28 overflow-hidden">
        <img
          src={stage.image}
          alt={`${stage.label} illustration`}
          className="h-full w-full object-cover transition-transform duration-500 group-hover:scale-105"
        />
        <div className="absolute inset-x-0 top-0 h-[3px]" style={{ backgroundColor: stage.color }} />
      </div>
      <div className="p-4">
        <div className="flex items-center justify-between">
          <h3 className="text-sm font-black text-slate-900">{stage.label}</h3>
          <span className="font-mono text-[10px] font-black tracking-widest" style={{ color: stage.color }}>
            {String(index + 1).padStart(2, '0')}
          </span>
        </div>
        <p className="mt-1.5 text-xs leading-relaxed text-slate-600">{stage.body}</p>
      </div>
    </GlassCard>
    {index < PATTERN.length - 1 && (
      <ArrowRight className="absolute -right-4 top-1/2 hidden h-4 w-4 -translate-y-1/2 text-slate-300 xl:block" />
    )}
  </Reveal>
);

/* ------------------------------------------------------- Problem blocks -- */

const ProblemHeader: React.FC<{
  index: number;
  eyebrow: string;
  title: React.ReactNode;
  narrative: string;
  pull?: string;
}> = ({ index, eyebrow, title, narrative, pull }) => (
  <Reveal>
    <div className="max-w-3xl">
      <span className="inline-flex items-center gap-2 rounded-full border border-rose-300/60 bg-rose-50 px-3 py-1 font-mono text-[11px] font-bold uppercase tracking-[0.2em] text-rose-600">
        <ShieldAlert className="h-3.5 w-3.5" /> Problem {String(index).padStart(2, '0')} — {eyebrow}
      </span>
      <h3 className="mt-4 text-2xl font-black tracking-tight text-slate-900 sm:text-3xl">{title}</h3>
      <p className="mt-3 text-base leading-relaxed text-slate-600">{narrative}</p>
      {pull && (
        <p className="mt-4 border-l-2 border-violet-400 pl-4 text-base font-bold italic text-violet-700">
          &ldquo;{pull}&rdquo;
        </p>
      )}
    </div>
  </Reveal>
);

type ProblemSpec = {
  index: number;
  eyebrow: string;
  title: React.ReactNode;
  narrative: string;
  pull?: string;
  spotlight: {
    icon: LucideIcon;
    eyebrow: string;
    title: string;
    blurb: string;
    bullets: string[];
    image: string;
    reverse?: boolean;
  };
};

const PROBLEMS: ProblemSpec[] = [
  {
    index: 1,
    eyebrow: 'The Hidden Trust Estate',
    title: (
      <>
        The trust estate is <Highlight>larger</Highlight> than the crypto estate
      </>
    ),
    narrative:
      'A hybrid ML-KEM rollout stalls for six weeks. Every vendor review blames the cryptography — and every theory is wrong. The root cause is an undocumented trust hierarchy buried in legacy middleware, absent from every inventory. The reviews were examining cryptography; the failure was hiding in trust.',
    pull: 'You cannot migrate what you have not discovered.',
    spotlight: {
      icon: Share2,
      eyebrow: 'Solved by Trust-State Discovery',
      title: 'Reconstruct the trust hierarchy as it actually runs',
      blurb:
        'Trust-State Discovery correlates assets, certificates, runtime crypto events, vendor assessments and migration jobs into one live trust graph — so the middleware nobody documented surfaces before it stalls your program, not six weeks into it.',
      bullets: [
        'Hidden-trust detection — runtime certificate fingerprints missing from inventory become migration blockers',
        'Self-signed and unknown-issuer trust paths flagged with evidence',
        'Certificate-replacement blast radius simulated before production changes',
        'Ecosystem Dependency Map ties every trust path to the services it carries',
      ],
      image: '/Digital_certificates.png',
    },
  },
  {
    index: 2,
    eyebrow: 'Inventory vs Trust',
    title: (
      <>
        A crypto inventory is <Highlight>not</Highlight> a trust inventory
      </>
    ),
    narrative:
      'Most organizations maintain some cryptographic inventory. Far fewer maintain a trust inventory — certificate chains, federation services, PKI anchors, vendor integrations, middleware. When migrations hit unexplained outages, the root cause is almost never the quantum-safe algorithm. It is an undocumented dependency.',
    pull: 'Trust is always bigger, older and more entangled than the inventory claims.',
    spotlight: {
      icon: ClipboardCheck,
      eyebrow: 'Solved by the 5-Checkpoint Migration Gate',
      title: 'No wave proceeds until the gate says it can',
      blurb:
        'The platform operationalizes Visibility → Ownership → Dependencies → Risk → Migration Gate as a scored workflow. Each checkpoint earns a ready, review or blocked state — and active migration jobs that overlap blocked trust paths are flagged and pause-recommended automatically.',
      bullets: [
        'Per-checkpoint scores with findings and a gate decision you can defend',
        'Gate-to-migration enforcement across Live Migration Ops',
        'Trust Chain Analyzer reconstructs certificate chains end to end',
        'Vendor PQC readiness treated as a first-class dependency',
      ],
      image: '/Governance_Compliance.png',
      reverse: true,
    },
  },
  {
    index: 3,
    eyebrow: 'The Cost of Trust',
    title: (
      <>
        Trust has become a <Highlight>runtime cost</Highlight>
      </>
    ),
    narrative:
      'Every certificate validation, TLS handshake, trust-chain lookup and revocation check now sits directly in the execution path of your applications. A trust decision is a latency decision, a scaling decision, a routing decision. Teams investigate applications, databases and networks — few investigate the cost of trust itself.',
    pull: 'How much does establishing trust cost right now, on this path, under these conditions?',
    spotlight: {
      icon: Gauge,
      eyebrow: 'Solved by TLS Telemetry — Trust Path Cost',
      title: 'Make the cost of trust a first-class metric',
      blurb:
        'The Trust Path Cost panel profiles every observed connection: handshake round-trips by TLS version, key-exchange compute class, and a ranked index of your costliest trust paths — including failure and retry cost — derived from real telemetry, never synthetic latency.',
      bullets: [
        'Handshake round-trip profile — TLS 1.3 1-RTT vs 2-RTT vs legacy stacks',
        'Key-exchange compute classes: ECDHE, DHE, RSA and hybrid ML-KEM',
        'Costliest observed trust paths ranked 0–100 with retry cost included',
        'Hybrid ML-KEM-768 bytes-on-wire outlook from FIPS 203 sizes × observed volume',
      ],
      image: '/monitoring.png',
    },
  },
  {
    index: 4,
    eyebrow: 'Beyond Network Scans',
    title: (
      <>
        Network scans only see what&rsquo;s <Highlight>active right now</Highlight>
      </>
    ),
    narrative:
      'Hardcoded cipher suites inside legacy binaries. Shadow IT services on undocumented endpoints. Vendor appliances running locked-down TLS stacks. Ephemeral containers spinning up with custom OpenSSL forks. Point-in-time network scanning captures none of it — and migrating on top of a partial picture is guessing.',
    pull: 'Guessing at enterprise scale means massive, unmapped operational risk.',
    spotlight: {
      icon: ScanSearch,
      eyebrow: 'Solved by Scanner + Shadow Crypto + Runtime Intelligence',
      title: 'Static, runtime and connector discovery — one inventory',
      blurb:
        'The scanner pipeline combines source-pattern detection, runtime cryptographic events and cloud-connector discovery, so the estate you migrate is the estate that actually exists — including the workloads no network scan ever sees.',
      bullets: [
        'Static detection of hardcoded suites, non-compliant curves and embedded keys',
        'Runtime crypto events show what systems actually negotiate in production',
        'Shadow-crypto flags on workloads absent from every inventory',
        'Cipher-suite, pattern and OID catalogs keep detection current',
      ],
      image: '/Scanner.png',
      reverse: true,
    },
  },
  {
    index: 5,
    eyebrow: 'Key Custody',
    title: (
      <>
        Do you know where your <Highlight>encryption keys</Highlight> live?
      </>
    ),
    narrative:
      'Hard-coded keys in applications. Shared keys across systems. Manual rotation. Expired and unmanaged certificates. Keys sitting in source repositories. No centralized inventory. Every secure system depends on cryptographic keys — very few organizations manage them like it.',
    pull: 'Encryption is only as strong as the keys that protect it.',
    spotlight: {
      icon: KeyRound,
      eyebrow: 'Solved by QKMS',
      title: 'One trust anchor for every key you own',
      blurb:
        'QKMS centralizes key inventory, lifecycle, governance and rotation — with PQC readiness scored per key, so modernizing the key estate happens before quantum computers force the issue.',
      bullets: [
        'Centralized key inventory with lifecycle state and ownership',
        'Automated rotation jobs and certificate lifecycle visibility',
        'Hard-coded key and exposed-secret detection via the scanner pipeline',
        'Hybrid key infrastructure and per-key PQC readiness',
      ],
      image: '/Encryption_key.png',
    },
  },
];

/* --------------------------------------------------- Five roadmap steps -- */

const ROADMAP: Array<{ title: string; body: string }> = [
  {
    title: 'Where is cryptography actually used?',
    body: 'PQC Scanner, Assets & CBOM and Shadow Crypto inventory every algorithm across apps, APIs, certificates and firmware.',
  },
  {
    title: 'Which assets are most critical?',
    body: 'Quantum Risk Scoring ranks every asset by business exposure, so prioritization is evidence — not opinion.',
  },
  {
    title: 'What depends on what?',
    body: 'The Ecosystem Dependency Map and Trust Chain Analyzer show the blast radius of every change before you make it.',
  },
  {
    title: 'Can the infrastructure support new standards?',
    body: 'The Hybrid Crypto Compatibility Lab and Vendor PQC Readiness validate ML-KEM and hybrid deployments ahead of rollout.',
  },
  {
    title: 'How is migration executed — and reversed?',
    body: 'Migration Planner sequences the waves; the Sandbox rehearses each one; Live Migration Ops executes with rollback ready.',
  },
];

/* ------------------------------------------------------- Platform grid -- */

const FEATURE_GRID: Feature[] = [
  {
    icon: ShieldAlert,
    title: 'Harvest Now, Decrypt Later Center',
    body: 'Find the long-lived secrets an adversary could record today and decrypt after Q-Day — and prioritize them first.',
  },
  {
    icon: FlaskConical,
    title: 'Hybrid Crypto Compatibility Lab',
    body: 'Test X25519 + ML-KEM and Ed25519 + ML-DSA hybrid deployments against your real stacks before production.',
  },
  {
    icon: Handshake,
    title: 'Vendor PQC Readiness',
    body: 'Track which suppliers can actually support your migration path — and which ones are the weak link.',
  },
  {
    icon: Activity,
    title: 'Drift Detection & Behavioral Analytics',
    body: 'Catch cryptographic drift the moment a workload deviates from its approved posture.',
  },
  {
    icon: Target,
    title: 'Quantum Risk Scoring',
    body: 'Explainable, confidence-scored risk on every asset — with the Shor/Grover threat model built in.',
  },
  {
    icon: Archive,
    title: 'Audit Vault & Compliance Evidence',
    body: 'Every governance finding links back to supporting evidence — traceable from dashboard to data source.',
  },
];

const FOOTER_GROUPS = [
  {
    title: 'Solutions',
    links: [
      { label: 'PQC Solutions', to: '/pqc-solutions' },
      { label: 'Qguard Messaging', to: '/qguard-messaging' },
      { label: 'Quantum Readiness', to: '/quantum-readiness-assessment' },
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
      { label: 'Live Dashboard', href: '/dashboard' },
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

export default function PqcSolutions() {
  return (
    <SolutionLayout
      homePath="/pqc-solutions"
      brandTitle="PQC Solutions"
      brandSubtitle="Six Problems // Solved"
      brandTagline="Post-Quantum Solutions"
      navLinks={NAV_LINKS}
      footerBlurb="The six problems that stall every post-quantum migration — hidden trust, missing inventories, runtime cost, shadow crypto, unmanaged keys and the enterprise roadmap — solved as evidence-backed workflows in one platform."
      footerGroups={FOOTER_GROUPS}
    >
      <span id="top" />

      {/* ------------------------------------------------------------------ Hero -- */}
      <section className="relative px-6 pb-16 pt-28 sm:pt-32">
        <div className="mx-auto grid max-w-[88rem] items-center gap-12 lg:grid-cols-[1.05fr_0.95fr]">
          <Reveal>
            <Kicker>QGuard Helix — PQC Solutions</Kicker>
            <h1 className="mt-5 text-4xl font-black leading-[1.05] tracking-tight text-slate-900 sm:text-6xl">
              The hard part isn&rsquo;t the algorithm.<br />
              It&rsquo;s everything <Highlight>connected</Highlight> to it.
            </h1>
            <p className="mt-5 max-w-xl text-base leading-relaxed text-slate-600 sm:text-lg">
              Hidden trust hierarchies. Shadow crypto. Unmanaged keys. The runtime cost of trust itself.
              Six hard problems stall every post-quantum migration — QGuard Helix turns each one into a
              solved, evidence-backed workflow.
            </p>
            <div className="mt-8 flex flex-wrap items-center gap-3">
              <GoldButton href="/register">Get Started</GoldButton>
              <DarkButton href="/#pricing">Compare Plans</DarkButton>
            </div>
            <div className="mt-8">
              <TrustStrip items={TRUST} />
            </div>
          </Reveal>

          {/* Signature: dark "Problem Ledger" console. Explicit slate/violet/emerald
              colours keep it intact under the light-theme override sheet. */}
          <Reveal delay={0.15}>
            <div className="relative overflow-hidden rounded-2xl border-2 border-slate-900 bg-[#040810] p-6 text-slate-200 shadow-[0_30px_90px_rgba(2,6,23,0.35)]">
              <div className="absolute inset-x-0 top-0 h-[3px] bg-gradient-to-r from-violet-500 via-fuchsia-500 to-cyan-400" />
              <div className="flex items-center justify-between">
                <span className="font-mono text-[10px] font-bold uppercase tracking-widest text-slate-400">
                  PROBLEM_LEDGER // SIX PROBLEMS, ONE PLATFORM
                </span>
                <span className="inline-flex items-center gap-1.5 font-mono text-[10px] font-bold text-emerald-400">
                  <span className="h-1.5 w-1.5 animate-pulse rounded-full bg-emerald-400" /> ALL TRACED
                </span>
              </div>

              <div className="mt-5 space-y-2">
                {LEDGER.map((row, i) => (
                  <LedgerRow key={row.problem} index={i} problem={row.problem} module={row.module} />
                ))}
              </div>

              <div className="mt-5 rounded-xl border border-violet-400/25 bg-violet-400/10 px-4 py-3 text-center">
                <span className="font-mono text-[9px] font-bold uppercase tracking-[0.18em] text-violet-200 sm:text-[10px]">
                  Visibility → Ownership → Dependencies → Risk → Migration Gate
                </span>
              </div>
            </div>
          </Reveal>
        </div>
      </section>

      {/* --------------------------------------------------------- The pattern -- */}
      <section id="pattern" className="mx-auto max-w-[88rem] scroll-mt-24 px-6 py-14">
        <SectionHeading
          kicker="The Pattern That Keeps Appearing"
          title={
            <>
              Before you migrate anything, <Highlight>discover everything</Highlight>
            </>
          }
          subtitle="The same framework surfaces in every stalled migration: know what exists, who owns it, what depends on it, what happens if it fails — and only then open the gate. The platform runs it as a scored, enforced workflow."
        />
        <div className="mt-12 grid grid-cols-2 gap-4 md:grid-cols-3 xl:grid-cols-5 xl:gap-8">
          {PATTERN.map((stage, i) => (
            <PatternCard key={stage.label} stage={stage} index={i} />
          ))}
        </div>
      </section>

      {/* ------------------------------------------------------- Six problems -- */}
      <section id="problems" className="mx-auto max-w-[88rem] scroll-mt-24 px-6 py-14">
        <SectionHeading
          kicker="Six Problems, Six Solutions"
          title={
            <>
              Every problem the field keeps hitting — <Highlight>solved</Highlight>
            </>
          }
          subtitle="Drawn from real enterprise migrations: the failures that stall programs for weeks are rarely cryptographic. Here is each one, and the capability built to end it."
        />

        <div className="mt-14 space-y-20">
          {PROBLEMS.map((p) => (
            <div key={p.index} className="space-y-8">
              <ProblemHeader
                index={p.index}
                eyebrow={p.eyebrow}
                title={p.title}
                narrative={p.narrative}
                pull={p.pull}
              />
              <ModuleSpotlight
                icon={p.spotlight.icon}
                eyebrow={p.spotlight.eyebrow}
                title={p.spotlight.title}
                blurb={p.spotlight.blurb}
                bullets={p.spotlight.bullets}
                image={p.spotlight.image}
                reverse={p.spotlight.reverse}
              />

              {/* Problem 4 carries the Shor vs Grover threat-model breakdown. */}
              {p.index === 4 && (
                <div className="space-y-8">
                  <div className="grid gap-5 lg:grid-cols-2">
                    <Reveal className="h-full">
                      <GlassCard className="h-full p-6" hover={false}>
                        <div className="flex items-center gap-3">
                          <span className="grid h-11 w-11 place-items-center rounded-xl border border-rose-300/60 bg-rose-50 text-rose-600">
                            <Atom className="h-5 w-5" />
                          </span>
                          <div>
                            <h4 className="text-lg font-black text-slate-900">Shor&rsquo;s algorithm</h4>
                            <span className="font-mono text-[10px] font-bold uppercase tracking-widest text-rose-600">
                              Sets the migration priority
                            </span>
                          </div>
                        </div>
                        <p className="mt-4 text-sm leading-relaxed text-slate-600">
                          Breaks the math behind RSA, Diffie-Hellman and ECC — the public-key trust
                          fabric inside TLS, certificates, software signing, VPNs, identity and banking
                          infrastructure. This is why PQC migration is urgent.
                        </p>
                      </GlassCard>
                    </Reveal>
                    <Reveal delay={0.08} className="h-full">
                      <GlassCard className="h-full p-6" hover={false}>
                        <div className="flex items-center gap-3">
                          <span className="grid h-11 w-11 place-items-center rounded-xl border border-amber-300/60 bg-amber-50 text-amber-600">
                            <Timer className="h-5 w-5" />
                          </span>
                          <div>
                            <h4 className="text-lg font-black text-slate-900">Grover&rsquo;s algorithm</h4>
                            <span className="font-mono text-[10px] font-bold uppercase tracking-widest text-amber-600">
                              Sets key-size planning
                            </span>
                          </div>
                        </div>
                        <p className="mt-4 text-sm leading-relaxed text-slate-600">
                          Speeds up brute-force search against symmetric keys. AES isn&rsquo;t dead — but
                          AES-128 security margins become a planning problem. Confusing the two threats
                          wrecks real migration strategies.
                        </p>
                      </GlassCard>
                    </Reveal>
                  </div>

                  <Reveal>
                    <GlassCard className="grid items-center gap-8 overflow-hidden p-6 sm:p-8 lg:grid-cols-[1fr_1.15fr]" hover={false}>
                      <div>
                        <span className="inline-flex items-center gap-2 rounded-full border border-violet-300/60 bg-violet-50 px-3 py-1 font-mono text-[11px] font-bold uppercase tracking-[0.2em] text-violet-700">
                          <Target className="h-3.5 w-3.5" /> Quantum Threat Model
                        </span>
                        <h4 className="mt-4 text-2xl font-black tracking-tight text-slate-900">
                          Every finding classified: Shor, Grover, legacy or protected
                        </h4>
                        <p className="mt-3 text-sm leading-relaxed text-slate-600">
                          Quantum Risk Scoring decomposes your estate into Shor-exposed public-key
                          findings, Grover symmetric-margin findings, legacy hashes and PQC-protected
                          assets — each with affected-asset counts, 7-day trends and roadmap guidance.
                        </p>
                        <p className="mt-4 border-l-2 border-violet-400 pl-4 text-base font-bold italic text-violet-700">
                          &ldquo;Shor sets the priority. The inventory sets the roadmap.&rdquo;
                        </p>
                      </div>
                      <motion.div
                        whileHover={{ scale: 1.02 }}
                        transition={{ duration: 0.4 }}
                        className="relative overflow-hidden rounded-xl border border-slate-200 bg-slate-950 shadow-[0_24px_70px_rgba(2,6,23,0.25)]"
                      >
                        <div className="absolute inset-x-0 top-0 z-10 h-[3px] bg-gradient-to-r from-rose-400 via-violet-500 to-cyan-400" />
                        <img
                          src="/Breaking_RSA_ECC.png"
                          alt="How quantum computing breaks RSA and ECC"
                          className="h-full max-h-[340px] w-full object-cover opacity-95"
                        />
                      </motion.div>
                    </GlassCard>
                  </Reveal>
                </div>
              )}
            </div>
          ))}

          {/* Problem 6 — the five roadmap questions, then the operating model. */}
          <div className="space-y-8">
            <ProblemHeader
              index={6}
              eyebrow="Enterprise Scale"
              title={
                <>
                  Readiness at enterprise scale is <Highlight>five questions</Highlight>
                </>
              }
              narrative="The conversation is no longer “should we prepare?” — it is “how do we prepare at enterprise scale?” The challenge isn’t choosing a quantum-resistant algorithm; it’s everything that comes before deployment. A practical roadmap starts with five questions, and the platform answers each one with a module."
              pull="The question isn’t whether PQC will affect your organization — it’s whether you’ll be ready before you have to be."
            />
            <div className="grid gap-4 sm:grid-cols-2 xl:grid-cols-5">
              {ROADMAP.map((step, i) => (
                <StepCard key={step.title} index={i} title={step.title} body={step.body} />
              ))}
            </div>
            <ModuleSpotlight
              icon={Route}
              eyebrow="Solved by the Readiness Engine & Migration Planner"
              title="From five answers to a crypto-agile operating model"
              blurb="The Quantum Readiness engine turns discovery into a scored posture; the Migration Planner sequences it into rehearsable, rollback-safe waves; and the Crypto Agility Engine keeps cryptography swappable as standards keep evolving — readiness as a capability, not a one-off project."
              bullets={[
                '9-stage migration workflow with validation checkpoints at every gate',
                'Sandbox simulation seeded from your real inventory — zero production risk',
                'Rollback and recovery validated before any cutover proceeds',
                'Crypto-agility scoring so the next standard is a pivot, not a program',
              ]}
              image="/Migration_Planner.png"
              reverse
            />
          </div>
        </div>
      </section>

      {/* ----------------------------------------------------- Platform grid -- */}
      <section id="platform" className="mx-auto max-w-[88rem] scroll-mt-24 px-6 py-14">
        <SectionHeading
          kicker="One Platform, Every Answer"
          title={
            <>
              The capabilities behind the <Highlight>solutions</Highlight>
            </>
          }
          subtitle="Discovery, intelligence, migration and governance modules share one live inventory — so security, platform and identity teams work from the same evidence."
        />
        <div className="mt-12 grid gap-5 sm:grid-cols-2 xl:grid-cols-3">
          {FEATURE_GRID.map((f, i) => (
            <FeatureCard key={f.title} feature={f} delay={(i % 3) * 0.06} />
          ))}
        </div>
      </section>

      {/* ----------------------------------------------------- Evidence band -- */}
      <section className="mx-auto max-w-[88rem] px-6 py-8">
        <Reveal>
          <GlassCard className="relative overflow-hidden p-8 sm:p-10" hover={false}>
            <div className="pointer-events-none absolute -right-16 -top-16 h-56 w-56 rounded-full bg-violet-300/25 blur-[80px]" />
            <div className="pointer-events-none absolute -bottom-16 -left-16 h-56 w-56 rounded-full bg-cyan-300/25 blur-[80px]" />
            <div className="relative z-10 grid items-center gap-8 lg:grid-cols-[1.2fr_1fr]">
              <div>
                <span className="inline-flex items-center gap-2 rounded-full border border-cyan-300/60 bg-cyan-50 px-3 py-1 font-mono text-[11px] font-bold uppercase tracking-[0.2em] text-cyan-700">
                  <Radar className="h-3.5 w-3.5" /> Evidence-grounded by design
                </span>
                <h2 className="mt-4 text-2xl font-black tracking-tight text-slate-900 sm:text-3xl">
                  Every number traces to a real observation
                </h2>
                <p className="mt-3 text-sm leading-relaxed text-slate-600">
                  Every metric on every dashboard derives from real scans, real certificates, real keys
                  and real runtime telemetry in your tenant. No synthetic posture, no fabricated
                  trust scores — an empty estate shows setup guidance, never invented numbers. That is
                  what makes the gate decision, the risk score and the board report defensible.
                </p>
                <div className="mt-5 flex flex-wrap gap-3">
                  <DarkButton href="/register">Get Started</DarkButton>
                  <GhostButton to="/quantum-readiness-assessment">Explore the Readiness Assessment</GhostButton>
                </div>
              </div>
              <motion.div
                whileHover={{ scale: 1.02 }}
                transition={{ duration: 0.4 }}
                className="relative overflow-hidden rounded-xl border border-slate-200 bg-slate-950 shadow-[0_24px_70px_rgba(2,6,23,0.25)]"
              >
                <div className="absolute inset-x-0 top-0 z-10 h-[3px] bg-gradient-to-r from-cyan-400 via-violet-500 to-rose-400" />
                <img
                  src="/Threat_Intelligence.png"
                  alt="Live quantum threat intelligence dashboard"
                  className="h-full max-h-[300px] w-full object-cover opacity-95"
                />
              </motion.div>
            </div>
          </GlassCard>
        </Reveal>
      </section>

      {/* ----------------------------------------------------------------- CTA -- */}
      <CTASection
        title="Six problems. One platform."
        body="Discover the trust estate you're actually running, triage Shor before Grover, put every key under management — and migrate through a gate you can defend."
        primary={{ label: 'Get Started', href: '/register' }}
        secondary={{ label: 'Compare Plans', href: '/#pricing' }}
      />
    </SolutionLayout>
  );
}
