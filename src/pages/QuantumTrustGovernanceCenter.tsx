/**
 * Quantum Trust & Governance Center — marketing overview (/quantum-trust-governance-center)
 *
 * Public "Learn More" page for the ELITE product. Reuses the exact QGuard
 * Messaging + Quantum Readiness Assessment design language (light theme,
 * GlassCard system, gold/cyan/violet accents, Framer Motion reveals) via the
 * shared SolutionLayout.
 *
 * Copy and modules derive from the Elite tier capabilities on the pricing page.
 * Console/score figures are an illustrative product preview — never live posture.
 */
import { motion } from 'motion/react';
import { GovernanceTrustHero } from './_governance-trust-hero';
import {
  Award,
  Boxes,
  Building2,
  ClipboardCheck,
  Clock,
  FileCheck,
  Fingerprint,
  KeyRound,
  Landmark,
  Layers,
  Lock,
  Network,
  Radar,
  Scale,
  ShieldCheck,
  Sparkles,
  type LucideIcon,
} from 'lucide-react';
import {
  SolutionLayout,
  Reveal,
  Highlight,
  SectionHeading,
  GlassCard,
  FeatureCard,
  DarkButton,
  GoldButton,
  GhostButton,
  CTASection,
  ScoreCard,
  ModuleSpotlight,
  type Feature,
  type Score,
} from './_solution-shared';

const GREEN = '#22c55e';
const CYAN = '#06b6d4';
const BLUE = '#3b82f6';
const VIOLET = '#8b5cf6';
const AMBER = '#f59e0b';
const GOLD = '#eab308';

const NAV_LINKS = [
  { label: 'Overview', href: '#top' },
  { label: 'Compliance', href: '#compliance' },
  { label: 'Capabilities', href: '#capabilities' },
  { label: 'Frameworks', href: '#frameworks' },
];

const SCORES: Score[] = [
  { label: 'SOC 2 Type II', value: 98, suffix: '%', detail: 'Controls mapped & evidenced', color: GREEN, ring: 98, icon: ShieldCheck },
  { label: 'PCI-DSS 4.0', value: 94, suffix: '%', detail: 'Requirements covered', color: CYAN, ring: 94, icon: Lock },
  { label: 'NIST PQC', value: 100, suffix: '%', detail: 'FIPS 203 / 204 / 205 aligned', color: BLUE, ring: 100, icon: FileCheck },
  { label: 'Custom Frameworks', value: 89, suffix: '%', detail: 'Your internal policy mapping', color: VIOLET, ring: 89, icon: ClipboardCheck },
  { label: 'QKMS Readiness', value: 91, suffix: '%', detail: 'Keys quantum-safe or hybrid', color: AMBER, ring: 91, icon: KeyRound },
  { label: 'Assets Governed', value: 5000, detail: 'Across the enterprise estate', color: GOLD, icon: Boxes },
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
    icon: KeyRound,
    eyebrow: 'Quantum Key Management System',
    title: 'One authority for every key you hold',
    blurb: 'A full QKMS gives you a single inventory, lifecycle and governance layer for keys across HSMs, cloud KMS and applications — with quantum-readiness scored on each one.',
    bullets: [
      'Complete key inventory across the estate',
      'Lifecycle: generation, rotation, retirement',
      'Governance and policy enforcement per key',
      'Quantum-readiness scoring on every key',
    ],
    image: '/Encryption_key.png',
  },
  {
    icon: Landmark,
    eyebrow: 'Crypto Governance & Policy',
    title: 'Set the policy once — enforce it everywhere',
    blurb: 'Define cryptographic policy centrally and hold the whole estate to it. Quantum governance, crypto policies and an audit vault keep every decision traceable and defensible.',
    bullets: [
      'Central cryptographic policy definition',
      'Enterprise-wide enforcement and drift alerts',
      'Audit vault with tamper-evident history',
      'Regulatory alignment built in',
    ],
    image: '/governance/policy-enforcement.webp',
    reverse: true,
  },
  {
    icon: FileCheck,
    eyebrow: 'Compliance & Audit Evidence',
    title: 'Prove compliance without a fire drill',
    blurb: 'Map controls to SOC 2, PCI-DSS 4.0, NIST and your own frameworks, and generate audit-ready evidence on demand — every status traceable back to the finding behind it.',
    bullets: [
      'SOC 2, PCI-DSS 4.0, NIST & custom mapping',
      'Evidence packages generated on demand',
      'Every status traces to supporting evidence',
      'Continuous, not point-in-time, assurance',
    ],
    image: '/governance/audit-evidence.webp',
  },
  {
    icon: Fingerprint,
    eyebrow: 'Continuous Trust Validation',
    title: 'Trust that is measured, not assumed',
    blurb: 'Validate identity, device and cryptographic trust continuously across your ecosystem — with evidence behind every trust score, so a green light actually means something.',
    bullets: [
      'Evidence-based identity & device trust',
      'Continuous validation across the ecosystem',
      'Trust-chain and PKI visibility',
      'Zero-trust posture, verifiable end to end',
    ],
    image: '/Security_authentication.png',
    reverse: true,
  },
];

const FEATURE_GRID: Feature[] = [
  { icon: Boxes, title: 'Key Inventory', body: 'A single source of truth for every key across HSMs, cloud KMS, PKI and applications.' },
  { icon: Layers, title: 'Key Lifecycle', body: 'Generation, rotation, escrow and retirement — governed by policy at every stage.' },
  { icon: Award, title: 'PKI & Certificates', body: 'Full certificate visibility and governance, from issuance to revocation and renewal.' },
  { icon: ClipboardCheck, title: 'Audit Vault', body: 'Tamper-evident evidence and a traceable history of every governance decision.' },
  { icon: Scale, title: 'Regulatory Mapping', body: 'Map your posture to SOC 2, PCI-DSS 4.0, NIST and custom frameworks in one place.' },
  { icon: ShieldCheck, title: 'Continuous Trust', body: 'Evidence-based, always-on validation of identity, device and cryptographic trust.' },
];

const FRAMEWORKS: Array<{ purpose: string; framework: string; standard: string }> = [
  { purpose: 'Security controls', framework: 'SOC 2 Type II', standard: 'AICPA' },
  { purpose: 'Cardholder data', framework: 'PCI-DSS 4.0', standard: 'PCI SSC' },
  { purpose: 'Post-quantum crypto', framework: 'FIPS 203 / 204 / 205', standard: 'NIST' },
  { purpose: 'National security', framework: 'CNSA 2.0', standard: 'NSA' },
  { purpose: 'Your policy', framework: 'Custom frameworks', standard: 'Mapped' },
];

const INCLUDED = [
  'Everything in Starter, Basic, and Pro',
  'Discover and govern up to 5,000 crypto assets',
  'Full QKMS overview, inventory, governance, and readiness',
  'SOC 2, PCI-DSS 4.0, NIST, and custom compliance mapping',
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
      { label: 'Live Dashboard', href: '/dashboard/qkms/overview' },
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

export default function QuantumTrustGovernanceCenter() {
  return (
    <SolutionLayout
      homePath="/quantum-trust-governance-center"
      brandTitle="Trust & Governance"
      brandSubtitle="Quantum Governance Center"
      brandTagline="Trust & Governance"
      navLinks={NAV_LINKS}
      footerBlurb="The enterprise trust anchor for your cryptographic estate — govern thousands of assets, run a full quantum key management system, and prove compliance across SOC 2, PCI-DSS 4.0, NIST and your own frameworks."
      footerGroups={FOOTER_GROUPS}
    >
      <span id="top" />

      <GovernanceTrustHero />

      {/* ---------------------------------------------------- Governance at scale -- */}
      <section className="mx-auto max-w-[88rem] px-6 py-12">
        <Reveal>
          <GlassCard className="grid items-center gap-8 overflow-hidden p-6 sm:p-8 lg:grid-cols-2" hover={false}>
            <div>
              <span className="inline-flex items-center gap-2 rounded-full border border-amber-300/60 bg-amber-50 px-3 py-1 font-mono text-[11px] font-bold uppercase tracking-[0.2em] text-amber-700">
                <Clock className="h-3.5 w-3.5" /> Governance is the hard part at scale
              </span>
              <h2 className="mt-4 text-3xl font-black tracking-tight text-slate-900 sm:text-4xl">
                Thousands of keys. One <Highlight>source of truth</Highlight>.
              </h2>
              <p className="mt-3 text-base leading-relaxed text-slate-600">
                At enterprise scale, the risk isn&rsquo;t knowing that PQC exists — it&rsquo;s governing thousands of
                keys and certificates, enforcing policy across teams, and proving it to an auditor on demand. The
                Trust &amp; Governance Center makes that a continuous, evidence-backed process instead of an annual scramble.
              </p>
              <div className="mt-6 grid grid-cols-3 gap-3">
                {[
                  { k: '5,000', v: 'Assets discovered & governed' },
                  { k: 'Full QKMS', v: 'Inventory, lifecycle, policy' },
                  { k: '4+', v: 'Compliance frameworks mapped' },
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
              <div className="absolute inset-x-0 top-0 z-10 h-[3px] bg-gradient-to-r from-amber-400 via-gold to-cyan-400" />
              <img src="/governance/estate-governance.webp" alt="Conceptual view of a central cryptographic trust core governing interconnected key and certificate assets" width={1440} height={960} loading="lazy" decoding="async" className="aspect-[3/2] max-h-[320px] w-full object-cover opacity-95" />
            </motion.div>
          </GlassCard>
        </Reveal>
      </section>

      {/* ------------------------------------------------------------ Compliance -- */}
      <section id="compliance" className="mx-auto max-w-[88rem] scroll-mt-24 px-6 py-14">
        <SectionHeading
          kicker="Continuous Compliance"
          title={<>One dashboard for every <Highlight>framework</Highlight></>}
          subtitle="Map controls once and watch coverage stay current — each percentage traceable back to the exact key, policy or finding behind it."
        />
        <div className="mt-12 grid grid-cols-1 gap-4 sm:grid-cols-2 xl:grid-cols-3">
          {SCORES.map((score, i) => (
            <ScoreCard key={score.label} score={score} delay={(i % 3) * 0.06} />
          ))}
        </div>
        <p className="mx-auto mt-6 max-w-2xl text-center text-xs leading-relaxed text-slate-500">
          Figures shown are an illustrative product preview. In production every score derives from your real
          inventory, policy and evidence — never fabricated.
        </p>
      </section>

      {/* ---------------------------------------------------------- Spotlights -- */}
      <section id="capabilities" className="mx-auto max-w-[88rem] scroll-mt-24 px-6 py-14">
        <SectionHeading
          kicker="Inside the Center"
          title={<>Keys, policy, compliance &mdash; <Highlight>one authority</Highlight></>}
          subtitle="The platform trust anchor: a full key management system, central crypto governance, and audit-ready compliance across the enterprise estate."
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

      {/* ------------------------------------------------------------ Enterprise -- */}
      <section className="mx-auto max-w-[88rem] px-6 py-8">
        <Reveal>
          <GlassCard className="relative overflow-hidden p-8 sm:p-10" hover={false}>
            <div className="pointer-events-none absolute -right-16 -top-16 h-56 w-56 rounded-full bg-amber-300/25 blur-[80px]" />
            <div className="pointer-events-none absolute -bottom-16 -left-16 h-56 w-56 rounded-full bg-cyan-300/25 blur-[80px]" />
            <div className="relative z-10 grid items-center gap-8 lg:grid-cols-[1.4fr_1fr]">
              <div>
                <span className="inline-flex items-center gap-2 rounded-full border border-amber-300/60 bg-amber-50 px-3 py-1 font-mono text-[11px] font-bold uppercase tracking-[0.2em] text-amber-700">
                  <Sparkles className="h-3.5 w-3.5" /> Enterprise trust anchor
                </span>
                <h2 className="mt-4 text-2xl font-black tracking-tight text-slate-900 sm:text-3xl">
                  Evidence your auditors and board can both follow
                </h2>
                <p className="mt-3 text-sm leading-relaxed text-slate-600">
                  Every trust score and compliance status cites the keys, policies and findings behind it. No black
                  boxes — just governance you can defend in a boardroom and in an audit, from the same source of truth.
                </p>
                <div className="mt-5 flex flex-wrap gap-3">
                  <DarkButton href="/#pricing">Choose Elite</DarkButton>
                  <GhostButton to="/post-quantum-migration-platform">Explore the Migration Platform</GhostButton>
                </div>
              </div>
              <div className="grid grid-cols-3 gap-3">
                {[
                  { icon: Radar, k: 'Traceable', tone: GOLD },
                  { icon: Building2, k: 'Enterprise', tone: VIOLET },
                  { icon: Network, k: 'Continuous', tone: CYAN },
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

      {/* ------------------------------------------------------------ Frameworks -- */}
      <section id="frameworks" className="mx-auto max-w-[88rem] scroll-mt-24 px-6 py-14">
        <SectionHeading
          kicker="Frameworks We Map To"
          title={<>Prove it against the standards that <Highlight>matter</Highlight></>}
          subtitle="Controls map to the frameworks your auditors already use — so a compliant badge is backed by real, traceable evidence."
        />
        <div className="mt-10">
          <Reveal>
            <GlassCard className="overflow-hidden" hover={false}>
              <div className="grid grid-cols-1 divide-y divide-slate-200 sm:grid-cols-2 sm:divide-x lg:grid-cols-5 lg:divide-y-0">
                {FRAMEWORKS.map((row) => (
                  <div key={row.framework} className="p-5">
                    <div className="font-mono text-[10px] font-bold uppercase tracking-widest text-slate-500">{row.purpose}</div>
                    <div className="mt-2 font-mono text-sm font-bold text-slate-900">{row.framework}</div>
                    <div className="mt-2 inline-flex rounded-full border border-gold/30 bg-gold/10 px-2 py-0.5 font-mono text-[10px] font-bold text-[#b8860b]">{row.standard}</div>
                  </div>
                ))}
              </div>
            </GlassCard>
          </Reveal>
        </div>
      </section>

      {/* ------------------------------------------------------------- Included -- */}
      <section id="included" className="mx-auto max-w-[88rem] scroll-mt-24 px-6 py-6">
        <div className="mx-auto max-w-4xl">
          <Reveal>
            <GlassCard className="p-8" hover={false}>
              <span className="inline-flex items-center gap-2 rounded-full border border-gold/40 bg-gold/10 px-3 py-1 font-mono text-[11px] font-bold uppercase tracking-[0.22em] text-[#b8860b]">
                <ShieldCheck className="h-3.5 w-3.5 text-gold" /> Everything in Elite
              </span>
              <div className="mt-4 flex flex-wrap items-baseline gap-x-2">
                <span className="font-mono text-4xl font-black text-slate-900">$199</span>
                <span className="font-mono text-sm text-slate-500">/mo</span>
                <span className="ml-2 rounded-full border border-gold/30 bg-gold/10 px-2 py-0.5 font-mono text-[10px] font-bold text-[#b8860b]">$150/mo billed yearly</span>
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
                <GoldButton to="/checkout?plan=Elite&cycle=yearly">Choose Elite</GoldButton>
                <GhostButton href="/#pricing">Compare all plans</GhostButton>
              </div>
            </GlassCard>
          </Reveal>
        </div>
      </section>

      {/* ----------------------------------------------------------------- CTA -- */}
      <CTASection
        title="Govern your estate and prove it — continuously"
        body="Run a full QKMS, enforce crypto policy across teams, and generate audit-ready evidence on demand, all from one enterprise command center."
        primary={{ label: 'Choose Elite', to: '/checkout?plan=Elite&cycle=yearly' }}
        secondary={{ label: 'Compare Plans', href: '/#pricing' }}
      />
    </SolutionLayout>
  );
}
