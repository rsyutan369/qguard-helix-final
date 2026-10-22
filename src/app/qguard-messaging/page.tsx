/**
 * QGuard Messaging — Overview (/qguard-messaging)
 * Showcases the combined application: Secure Chat + Quantum Vault, and what is
 * new in 1.3.8 → 1.5.x. Every capability shown is taken from
 * qguard-messaging/CHANGELOG.md and the feature roadmap; opt-in, platform-limited
 * and unreviewed features are tagged as such.
 */
import { Link } from 'react-router-dom';
import { motion } from 'motion/react';
import {
  ShieldCheck,
  MessageSquareLock,
  Lock,
  KeyRound,
  Phone,
  Server,
  EyeOff,
  Cpu,
  Layers,
  ArrowRight,
} from 'lucide-react';
import {
  MessagingLayout,
  Reveal,
  Highlight,
  Kicker,
  DarkButton,
  GoldButton,
  GhostButton,
  SectionHeading,
  GlassCard,
  FeatureCard,
  TrustStrip,
  AlgoSuiteTable,
  CTASection,
  DownloadButton,
  InstallerIntegrity,
  type Feature,
} from './_shared';
import { Aurora, Marquee, StageFrame, Tilt3D } from './_motion';
import { HeroLinkScene } from './_scenes-hero';
import { Block, FeatureAtlas, NextUp, NumbersStrip, PlatformMatrix, ReleaseRail, StraightTalk } from './_catalog';
import { MessengerComparison } from './_comparison';

const TRUST = ['NIST FIPS 203', 'FIPS 204', 'End-to-End Encrypted', 'Zero-Knowledge', 'Hybrid Post-Quantum'];

const TICKER = [
  'Protection badge with evidence',
  'Verify contacts · call phrase',
  'Post-quantum session ratchet (opt-in)',
  'Groups up to 32 · large groups up to 1,000',
  'Mobile-number sign-in · QR device linking',
  'Block & Restrict, enforced by the server',
  'Group video calls',
  'Channels',
  'Social recovery',
  'Encrypted history backup',
  'Duress PIN · panic wipe',
  'Offline & nearby delivery',
  'PIN-bound vault containers',
  'Helix posture import',
];

const COMBINED_FEATURES: Feature[] = [
  { icon: ShieldCheck, title: 'Post-Quantum by Default', body: 'Every message, call and chat file is secured with ML-KEM-1024 and ML-DSA; vault containers are signed with ML-DSA-87 under AES-256 keys — NIST-standardized algorithms built to withstand quantum computers.' },
  { icon: Layers, title: 'Hybrid Encryption', body: 'Classical and post-quantum combined, bound to the transcript. An attacker would have to break both — built to resist "harvest now, decrypt later".' },
  { icon: Lock, title: 'True End-to-End', body: 'Encrypted on your device, decrypted only on the other end. The server stores ciphertext and the routing metadata it needs to deliver it — never your content.' },
  { icon: EyeOff, title: 'Zero-Knowledge', body: 'We store ciphertext, public keys and minimal routing metadata — never your private keys, plaintext, or recovery secrets. No message escrow exists for organisations either.' },
  { icon: Phone, title: 'Post-Quantum Encrypted Calls', body: '1:1 and three-person calls with per-frame encryption, a fresh post-quantum key per link, an authenticated caller and a verifiable call phrase.' },
  { icon: KeyRound, title: 'Forward Secrecy You Can Inspect', body: 'Prekeys rotate and retire by default; an opt-in ratchet gives every message its own key. The app tells you which one is protecting each device.' },
  { icon: Server, title: 'On-Device Vault', body: 'The Quantum Vault encrypts files and folders entirely on your device — PIN-bound containers, nothing ever uploaded.' },
  { icon: Cpu, title: 'Native Crypto Core', body: 'Core cryptography runs natively in Rust on-device, and a start-up self-test measures it rather than assuming it.' },
];

function ProductSpotlight({
  to,
  eyebrow,
  title,
  blurb,
  bullets,
  image,
  icon: Icon,
  reverse = false,
}: {
  to: string;
  eyebrow: string;
  title: string;
  blurb: string;
  bullets: string[];
  image: string;
  icon: typeof Lock;
  reverse?: boolean;
}) {
  return (
    <Reveal>
      <GlassCard className="grid items-center gap-8 overflow-hidden p-6 sm:p-8 lg:grid-cols-2" hover={false}>
        <div className={reverse ? 'lg:order-2' : ''}>
          <span className="inline-flex items-center gap-2 rounded-full border border-gold/40 bg-gold/10 px-3 py-1 font-mono text-[11px] font-bold uppercase tracking-[0.2em] text-[#b8860b]">
            <Icon className="h-3.5 w-3.5 text-gold" /> {eyebrow}
          </span>
          <h3 className="mt-4 text-2xl font-black tracking-tight text-slate-900 sm:text-3xl">{title}</h3>
          <p className="mt-3 text-sm leading-relaxed text-slate-600">{blurb}</p>
          <ul className="mt-5 space-y-2.5">
            {bullets.map((b) => (
              <li key={b} className="flex items-start gap-2.5 text-sm text-slate-700">
                <ShieldCheck className="mt-0.5 h-4 w-4 shrink-0 text-gold" />
                <span>{b}</span>
              </li>
            ))}
          </ul>
          <div className="mt-6">
            <DarkButton to={to}>Explore {eyebrow}</DarkButton>
          </div>
        </div>
        <div className={reverse ? 'lg:order-1' : ''}>
          <Tilt3D max={6}>
            <motion.div
              whileHover={{ scale: 1.02 }}
              transition={{ duration: 0.4 }}
              className="relative overflow-hidden rounded-xl border border-slate-200 bg-slate-950 shadow-[0_24px_70px_rgba(2,6,23,0.25)]"
              style={{ transform: 'translateZ(30px)' }}
            >
              <div className="absolute inset-x-0 top-0 z-10 h-[3px] bg-gradient-to-r from-cyan-400 via-gold to-violet-500" />
              <img src={image} alt={title} className="h-full max-h-[320px] w-full object-cover opacity-95" />
            </motion.div>
          </Tilt3D>
        </div>
      </GlassCard>
    </Reveal>
  );
}

export default function QguardMessagingOverview() {
  return (
    <MessagingLayout>
      {/* Hero */}
      <section className="relative px-6 pb-16 pt-28 sm:pt-32">
        <Aurora />
        <div className="mx-auto grid max-w-[88rem] items-center gap-12 grid-cols-[minmax(0,1fr)] lg:grid-cols-2">
          <Reveal>
            <Kicker>QGuard Messaging</Kicker>
            <h1 className="mt-5 text-4xl font-black leading-[1.05] tracking-tight text-slate-900 sm:text-6xl">
              One app.<br />Quantum-safe <Highlight>chat</Highlight> &amp; <Highlight>vault</Highlight>.
            </h1>
            <p className="mt-5 max-w-xl text-base leading-relaxed text-slate-600 sm:text-lg">
              End-to-end encrypted chat, groups, channels and calls, plus a strictly on-device Quantum Vault — protected by NIST post-quantum cryptography. Now with protection you can see, contacts you can verify, and recovery that does not depend on us.
            </p>
            <p className="mt-4 max-w-xl border-l-2 border-gold pl-4 text-sm leading-relaxed text-slate-700 sm:text-base">
              QGuard Messaging protects your chats, voice and video calls, files and vault with post-quantum encryption by default. It uses NIST-standardized ML-KEM and ML-DSA, so what you send today stays protected against tomorrow's quantum computers. For Windows and Android.
            </p>
            <div className="mt-8 flex flex-wrap items-center gap-3">
              <DownloadButton />
              <GoldButton href="/login">Launch the App</GoldButton>
              <GhostButton to="/qguard-messaging/secure-chat">Explore Secure Chat</GhostButton>
            </div>
            <InstallerIntegrity className="mt-5" />
            <div className="mt-8">
              <TrustStrip items={TRUST} />
            </div>
          </Reveal>

          <Reveal delay={0.15}>
            <StageFrame
              title="QGUARD_MESSAGING // SECURE"
              bodyClassName="!px-2 !py-2"
              note={
                <>
                  <span className="inline-flex items-center gap-2"><span className="qm-live-dot" aria-hidden />Relay holds ciphertext, public keys and routing metadata — never plaintext or private keys.</span>
                  <span>Move your pointer over the scene.</span>
                </>
              }
            >
              <HeroLinkScene />
            </StageFrame>
          </Reveal>
        </div>
      </section>

      {/* Capability ticker */}
      <section className="relative py-6" aria-label="What is in the app">
        <Marquee items={TICKER} />
      </section>

      {/* Two product spotlights */}
      <section className="mx-auto max-w-[88rem] space-y-8 px-6 py-12">
        <ProductSpotlight
          to="/qguard-messaging/secure-chat"
          eyebrow="Secure Chat"
          icon={MessageSquareLock}
          title="Conversations built for the quantum era"
          blurb="End-to-end encrypted messages, groups, channels, voice & video calls and files — with a protection badge that shows its evidence, contacts you can verify, and recovery you control."
          bullets={[
            'Hybrid ML-KEM-1024 sealing on every message, with an opt-in per-message ratchet',
            'Verify a contact, then prove it is them on a call with a four-word phrase',
            'Groups up to 32, large groups and channels up to 1,000, three-person video calls, screen sharing on desktop',
            'Duress PIN, panic wipe, social recovery and offline delivery when the relay is down',
          ]}
          image="/Secure_communication.png"
        />
        <ProductSpotlight
          to="/qguard-messaging/quantum-vault"
          eyebrow="Quantum Vault"
          icon={Lock}
          title="Your files, sealed for the quantum age"
          blurb="Encrypt any file or folder on your device into a sealed, tamper-evident container. Strictly local and zero-knowledge — your data never leaves your machine."
          bullets={[
            'PIN-bound .qvault v5: the vault lock is enforced by the cryptography',
            'Tamper-evident: any change, reorder or truncation is detected and refused, at any file or folder size',
            'Share to a person with a Portable Hybrid Identity — never your device key',
            'Quantum-safe offline recovery, with enterprise dual-control for teams',
          ]}
          image="/helix-features/QuantumVault3.png"
          reverse
        />
      </section>

      {/* Numbers */}
      <Block
        kicker="By design"
        title={<>Limits you can <Highlight>plan around</Highlight></>}
        subtitle="Numbers that come straight from the implementation, so what you read here is what the app enforces."
      >
        <NumbersStrip />
      </Block>

      {/* Comparison */}
      <Block
        kicker="How it compares"
        title={<>Post-quantum where others are <Highlight>still classical</Highlight></>}
        subtitle="QGuard Messaging next to Signal, WhatsApp and Telegram — feature by feature, from public documentation. Where others lead today, we say so."
      >
        <Reveal><MessengerComparison /></Reveal>
      </Block>

      {/* Feature atlas */}
      <section className="relative mx-auto max-w-[88rem] px-6 py-16">
        <Aurora />
        <SectionHeading
          kicker="Feature atlas"
          title={<>Everything that is <Highlight>new</Highlight>, in one place</>}
          subtitle="Filter by what you care about. Each card says when it arrived and whether it is on by default, opt-in, platform-specific or needs setup."
        />
        <FeatureAtlas />
      </section>

      {/* Release rail */}
      <Block kicker="What shipped" title={<>From authenticated messages to <Highlight>provable protection</Highlight></>} subtitle="The security releases, the 1.4 line and 1.5, in order.">
        <ReleaseRail />
      </Block>

      {/* Combined features */}
      <section className="mx-auto max-w-[88rem] px-6 py-16">
        <SectionHeading
          kicker="Why QGuard Messaging"
          title={<>Enterprise-grade, <Highlight>quantum-safe</Highlight> by design</>}
          subtitle="Both products share the same hardened cryptographic foundation — built on NIST standards and self-tested every time the app starts."
        />
        <div className="mt-12 grid gap-5 sm:grid-cols-2 lg:grid-cols-4">
          {COMBINED_FEATURES.map((f, i) => (
            <FeatureCard key={f.title} feature={f} delay={(i % 4) * 0.06} />
          ))}
        </div>
      </section>

      {/* Algorithm suite */}
      <section className="mx-auto max-w-[88rem] px-6 py-10">
        <SectionHeading kicker="Cryptographic Foundation" title="The exact suite" subtitle="Standards-based, hybrid, and post-quantum across messaging, calls, and the vault." />
        <div className="mt-10">
          <Reveal><AlgoSuiteTable /></Reveal>
        </div>
        <p className="mx-auto mt-4 max-w-2xl text-center text-xs leading-relaxed text-slate-500">
          ML-KEM is used for key encapsulation only — it protects the keys that protect your data. AES-256-GCM encrypts the content. Auto-updates are signed with Ed25519 (minisign) because the updater has no post-quantum option.
        </p>
      </section>

      {/* Platforms + next */}
      <Block narrow kicker="Where it runs" title="What runs where" subtitle="We list what is not there yet, too.">
        <Reveal><PlatformMatrix /></Reveal>
        <div className="mt-10">
          <h3 className="mb-4 text-center font-mono text-[11px] font-bold uppercase tracking-[0.22em] text-slate-500">On the roadmap — not available yet</h3>
          <NextUp />
        </div>
      </Block>

      {/* Straight talk */}
      <Block narrow kicker="Straight talk" title={<>What we <Highlight>don't</Highlight> claim</>} subtitle="A security product should tell you where its guarantees stop.">
        <Reveal><StraightTalk /></Reveal>
      </Block>

      {/* Quick links band */}
      <section className="mx-auto max-w-[88rem] px-6 py-8">
        <div className="grid gap-5 sm:grid-cols-2">
          {[
            { to: '/qguard-messaging/secure-chat', icon: MessageSquareLock, title: 'Secure Chat', body: 'Messaging, groups, calls & recovery — quantum-safe and end-to-end encrypted.' },
            { to: '/qguard-messaging/quantum-vault', icon: Lock, title: 'Quantum Vault', body: 'On-device, zero-knowledge file encryption with quantum-safe recovery.' },
          ].map((c, i) => (
            <Reveal key={c.to} delay={i * 0.08}>
              <Link to={c.to} className="block no-underline">
                <GlassCard className="group flex items-center gap-5 p-6">
                  <span className="flex h-14 w-14 shrink-0 items-center justify-center rounded-2xl border border-gold/30 bg-gold/10 text-[#b8860b]">
                    <c.icon className="h-7 w-7" />
                  </span>
                  <div className="min-w-0 flex-1">
                    <div className="flex items-center gap-2 text-lg font-bold text-slate-900">
                      {c.title}
                      <ArrowRight className="h-4 w-4 text-gold transition-transform group-hover:translate-x-1" />
                    </div>
                    <p className="mt-1 text-sm text-slate-600">{c.body}</p>
                  </div>
                </GlassCard>
              </Link>
            </Reveal>
          ))}
        </div>
      </section>

      <CTASection
        title="Private by default. Quantum-safe by design."
        body="Start using QGuard Messaging — end-to-end encrypted chat and an on-device quantum vault, with no message content for us to read or leak."
        primary={{ label: 'Launch the App', href: '/login' }}
        secondary={{ label: 'View Quantum Vault', to: '/qguard-messaging/quantum-vault' }}
      />
    </MessagingLayout>
  );
}
