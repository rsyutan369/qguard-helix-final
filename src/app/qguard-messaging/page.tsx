/**
 * QGuard Messaging — Overview (/qguard-messaging)
 * Showcases the combined application: Secure Chat + Quantum Vault, and what is
 * new in 1.3.8 → 1.5.x and the Quantum Vault Storage line. Every capability shown is taken from
 * qguard-messaging/CHANGELOG.md and the feature roadmap; opt-in, platform-limited
 * and unreviewed features are tagged as such.
 */
import { Link } from 'react-router-dom';
import type { ReactNode } from 'react';
import { MessagingBuildScope, SecurityCoverage } from './_security-coverage';
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
  GhostButton,
  SectionHeading,
  GlassCard,
  FeatureCard,
  TrustStrip,
  CTASection,
  DownloadButton,
  InstallerIntegrity,
  type Feature,
} from './_shared';
import { Aurora, Marquee, StageFrame, Tilt3D } from './_motion';
import { HeroLinkScene, HeroVaultScene } from './_scenes-hero';
import { LocalWorkflowLink, LocalWorkflows } from './_local-workflows';
import { Block, FeatureAtlas, NextUp, NumbersStrip, PlatformMatrix, ReleaseRail, StraightTalk, VaultNewGrid } from './_catalog';

const TRUST = ['Encrypted Chat & Calls', 'Local Vault Encryption', 'Hybrid Key Establishment'];

const TICKER = [
  'Protection badge with evidence',
  'Verify contacts · call phrase',
  'Post-quantum session ratchet (opt-in)',
  'Groups up to 32 · large groups up to 1,000',
  'Mobile-number sign-in · QR device linking',
  'Block & Restrict on supported relays',
  'Group video calls',
  'Channels',
  'Social recovery',
  'Encrypted history backup',
  'Duress PIN · panic wipe',
  'Offline & nearby delivery',
  'PIN-bound vault containers',
  'Quantum Vault Storage',
  'Draw-pattern vault unlock',
  'Hidden vaults',
  'Encrypted vault backup (opt-in)',
  'Share vault files with QGuard users',
  'Helix posture import',
];

const COMBINED_FEATURES: Feature[] = [
  { icon: ShieldCheck, title: 'Post-Quantum Key Establishment', body: 'Chat and calls use X25519 with ML-KEM-1024. Mesh and XFER use X25519 with ML-KEM-768. The standard local Vault uses AES-256-GCM and signed file headers.' },
  { icon: Layers, title: 'Hybrid Encryption', body: 'Classical and post-quantum combined, bound to the transcript. The hybrid exchange is designed to reduce the risk of “harvest now, decrypt later.”' },
  { icon: Lock, title: 'End-to-End Encryption', body: 'Encrypted on your device, decrypted only on the other end. The server stores ciphertext and the routing metadata it needs to deliver it — never your content.' },
  { icon: EyeOff, title: 'Relay Visibility', body: 'The relay handles ciphertext, public keys and routing metadata. If you use the optional AI assistant, selected text goes to the provider you configured.' },
  { icon: Phone, title: 'Post-Quantum Encrypted Calls', body: '1:1 and three-person calls with per-frame encryption, a fresh post-quantum key per link, an authenticated caller and a verifiable call phrase.' },
  { icon: KeyRound, title: 'Forward Secrecy You Can Inspect', body: 'Direct chat uses rotating signed prekeys. Compatible peers can opt into a session ratchet with per-message keys.' },
  { icon: Server, title: 'On-Device Vault', body: 'The Quantum Vault encrypts files and folders on your device in PIN-bound containers. Cloud backup and in-app sharing are optional. Whole-folder sealing is desktop-only.' },
  { icon: Cpu, title: 'Native Crypto Core', body: 'Core cryptography runs natively in Rust on-device, and a start-up self-test measures it rather than assuming it.' },
];

function ProductSpotlight({
  to,
  eyebrow,
  title,
  blurb,
  bullets,
  visual,
  icon: Icon,
  reverse = false,
}: {
  to: string;
  eyebrow: string;
  title: string;
  blurb: string;
  bullets: string[];
  visual: ReactNode;
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
              {visual}
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
              Secure chat. Local sharing. <Highlight>Quantum Vault</Highlight>.
            </h1>
            <p className="mt-5 max-w-xl text-base leading-relaxed text-slate-600 sm:text-lg">
              End-to-end encrypted chat and calls, plus an encrypted on-device Vault. Use XFER to share files and Offgrid Mesh to message trusted peers over compatible local links.
            </p>
            <p className="mt-4 max-w-xl border-l-2 border-gold pl-4 text-sm leading-relaxed text-slate-700 sm:text-base">
              Chat, calls and local transfer use hybrid post-quantum key establishment. Vault files use AES-256-GCM, with different key protection for local storage, sharing and recovery.
            </p>
            <MessagingBuildScope />
            <div className="mt-8 flex flex-wrap items-center gap-3">
              <DownloadButton />
              <GhostButton to="/qguard-messaging/secure-chat">Explore Secure Chat</GhostButton>
              <LocalWorkflowLink>Explore XFER and Offgrid Mesh</LocalWorkflowLink>
            </div>
            <InstallerIntegrity className="mt-5" />
            <div className="mt-8">
              <TrustStrip items={TRUST} />
            </div>
          </Reveal>

          <Reveal delay={0.15}>
            <StageFrame
              title="Messaging encryption illustration"
              bodyClassName="!px-2 !py-2"
              note={
                <>
                  <span className="inline-flex items-center gap-2"><span className="qm-live-dot" aria-hidden />The relay handles ciphertext, public keys and routing metadata.</span>
                  <span>Move your pointer over the scene.</span>
                </>
              }
            >
              <HeroLinkScene />
            </StageFrame>
          </Reveal>
        </div>
      </section>

      <LocalWorkflows page="overview" />

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
            'Hybrid ML-KEM-1024 for direct chat envelopes and shared group key delivery; optional session ratchet',
            'Compare a safety number and use a four-word phrase to check a paired device on a 1:1 call',
            'Groups up to 32, large groups and channels up to 1,000, three-person video calls, screen sharing on desktop',
            'Duress PIN, panic wipe, social recovery and offline delivery when the relay is down',
          ]}
          visual={<img src="/Secure_communication.png" alt="" loading="lazy" className="h-full max-h-[320px] w-full object-cover opacity-95" />}
        />
        <ProductSpotlight
          to="/qguard-messaging/quantum-vault"
          eyebrow="Quantum Vault"
          icon={Lock}
          title="Your files, sealed for the quantum age"
          blurb="Encrypt files on your device, or seal a whole folder on desktop. Keep files in a local encrypted library with password, PIN or supported pattern unlock."
          bullets={[
            'PIN-bound .qvault v5: the vault lock is enforced by the cryptography',
            'Authenticated chunks reject modification, reordering and truncation',
            'Vault Storage with sealed file names, opt-in encrypted backup and sharing with QGuard users',
            'Draw-pattern unlock and hidden vaults the app never lists',
          ]}
          visual={<StageFrame title="Standard Vault container"><HeroVaultScene /></StageFrame>}
          reverse
        />
      </section>

      {/* New in the vault */}
      <Block
        kicker="New in the Quantum Vault"
        title={<>A vault that <Highlight>keeps your files</Highlight> — and can keep a secret</>}
        subtitle="Vault Storage, encrypted backup across your devices, sharing, pattern unlock and hidden vaults — with signed v5 containers for the standard library and a separate format for hidden vaults."
      >
        <VaultNewGrid compact />
        <div className="mt-6 flex justify-center">
          <DarkButton to="/qguard-messaging/quantum-vault">See the new vault features</DarkButton>
        </div>
      </Block>

      {/* Numbers */}
      <Block
        kicker="By design"
        title={<>Limits you can <Highlight>plan around</Highlight></>}
        subtitle="Limits from the reviewed app source. Your installed build and relay configuration may differ."
      >
        <NumbersStrip />
      </Block>

      {/* Security coverage */}
      <Block
        kicker="Security by workflow"
        title={<>What protects <Highlight>each feature</Highlight></>}
        subtitle="The encryption, signatures and key exchange depend on what you are doing."
      >
        <Reveal><SecurityCoverage /></Reveal>
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
      <Block kicker="Release history" title={<>From authenticated messages to <Highlight>visible protection</Highlight></>} subtitle="Selected releases and newer features in the app source.">
        <ReleaseRail />
      </Block>

      {/* Combined features */}
      <section className="mx-auto max-w-[88rem] px-6 py-16">
        <SectionHeading
          kicker="Why QGuard Messaging"
          title={<>How QGuard <Highlight>protects your data</Highlight></>}
          subtitle="Windows and Android share a Rust cryptography core. Calls also use the device’s WebView for media encryption."
        />
        <div className="mt-12 grid gap-5 sm:grid-cols-2 lg:grid-cols-4">
          {COMBINED_FEATURES.map((f, i) => (
            <FeatureCard key={f.title} feature={f} delay={(i % 4) * 0.06} />
          ))}
        </div>
      </section>

      {/* Algorithm suite */}
      <section className="mx-auto max-w-[88rem] px-6 py-10">
        <p className="mx-auto mt-4 max-w-2xl text-center text-xs leading-relaxed text-slate-500">
          Windows auto-updates are signed with Ed25519 (minisign). This is separate from the signatures on messages and Vault files.
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
            { to: '/qguard-messaging/secure-chat', icon: MessageSquareLock, title: 'Secure Chat', body: 'Direct messages, groups, calls, contact verification and recovery.' },
            { to: '/qguard-messaging/quantum-vault', icon: Lock, title: 'Quantum Vault', body: 'On-device file encryption, encrypted storage and backup, pattern unlock and hidden vaults.' },
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
        title="Get QGuard Messaging for Windows"
        body="Install QGuard Messaging to use Secure Chat and Quantum Vault. Web sign-in manages your account and download access."
        secondary={{ label: 'View Quantum Vault', to: '/qguard-messaging/quantum-vault' }}
      />
    </MessagingLayout>
  );
}
