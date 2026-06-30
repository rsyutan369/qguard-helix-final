/**
 * QGuard Messaging — Overview (/qguard-messaging)
 * Showcases the combined application: Secure Chat + Quantum Vault.
 * Light theme matching the QGuard Helix homepage.
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
  type Feature,
} from './_shared';

const TRUST = ['NIST FIPS 203', 'FIPS 204', 'End-to-End Encrypted', 'Zero-Knowledge', 'Hybrid Post-Quantum'];

const COMBINED_FEATURES: Feature[] = [
  { icon: ShieldCheck, title: 'Post-Quantum by Default', body: 'Every message, call, and file is secured with ML-KEM-1024 and ML-DSA — the NIST-standardized algorithms built to withstand quantum computers.' },
  { icon: Layers, title: 'Hybrid Encryption', body: 'Classical and post-quantum combined. An attacker would have to break both — safe even from "harvest now, decrypt later".' },
  { icon: Lock, title: 'True End-to-End', body: 'Encrypted on your device, decrypted only on the other end. The server only ever sees ciphertext.' },
  { icon: EyeOff, title: 'Zero-Knowledge', body: 'We store ciphertext and public keys — never your private keys, plaintext, or recovery secrets.' },
  { icon: Phone, title: 'Quantum-Encrypted Calls', body: '1:1 voice and video with per-frame encryption and a fresh post-quantum key for every call.' },
  { icon: KeyRound, title: 'Forward Secrecy', body: 'A fresh key for every message and file. Compromising one key never exposes the rest.' },
  { icon: Server, title: 'On-Device Vault', body: 'The Quantum Vault encrypts files and folders entirely on your device — nothing is ever uploaded.' },
  { icon: Cpu, title: 'Native Crypto Core', body: 'Core cryptography runs natively in Rust on-device, not in browser JavaScript.' },
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
          <motion.div
            whileHover={{ scale: 1.02 }}
            transition={{ duration: 0.4 }}
            className="relative overflow-hidden rounded-xl border border-slate-200 bg-slate-950 shadow-[0_24px_70px_rgba(2,6,23,0.25)]"
          >
            <div className="absolute inset-x-0 top-0 z-10 h-[3px] bg-gradient-to-r from-cyan-400 via-gold to-violet-500" />
            <img src={image} alt={title} className="h-full max-h-[320px] w-full object-cover opacity-95" />
          </motion.div>
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
        <div className="mx-auto grid max-w-[88rem] items-center gap-12 lg:grid-cols-[1.1fr_0.9fr]">
          <Reveal>
            <Kicker>QGuard Messaging</Kicker>
            <h1 className="mt-5 text-4xl font-black leading-[1.05] tracking-tight text-slate-900 sm:text-6xl">
              One app.<br />Quantum-safe <Highlight>chat</Highlight> &amp; <Highlight>vault</Highlight>.
            </h1>
            <p className="mt-5 max-w-xl text-base leading-relaxed text-slate-600 sm:text-lg">
              QGuard Messaging combines end-to-end encrypted Secure Chat and a strictly on-device Quantum Vault — protected by NIST post-quantum cryptography. Your conversations and files stay private, even from us.
            </p>
            <div className="mt-8 flex flex-wrap items-center gap-3">
              <GoldButton href="/login">Launch the App</GoldButton>
              <GhostButton to="/qguard-messaging/secure-chat">Explore Secure Chat</GhostButton>
            </div>
            <div className="mt-8">
              <TrustStrip items={TRUST} />
            </div>
          </Reveal>

          {/* Dark contrast panel (matches the homepage hero card) */}
          <Reveal delay={0.15}>
            <div className="relative overflow-hidden rounded-2xl border-2 border-slate-900 bg-[#040810] p-6 text-white shadow-[0_30px_90px_rgba(2,6,23,0.35)]">
              <div className="absolute inset-x-0 top-0 h-[3px] bg-gradient-to-r from-cyan-400 via-gold to-violet-500" />
              <div className="flex items-center justify-between">
                <span className="font-mono text-[10px] font-bold uppercase tracking-widest text-slate-400">QGUARD_MESSAGING // SECURE</span>
                <span className="inline-flex items-center gap-1.5 font-mono text-[10px] font-bold text-emerald-400">
                  <span className="h-1.5 w-1.5 animate-pulse rounded-full bg-emerald-400" /> E2EE ACTIVE
                </span>
              </div>
              <div className="mt-6 grid grid-cols-2 gap-3">
                {[
                  { icon: MessageSquareLock, label: 'Secure Chat', value: 'ML-KEM-1024' },
                  { icon: Lock, label: 'Quantum Vault', value: 'AES-256-GCM' },
                  { icon: Phone, label: 'Calls', value: 'Per-frame E2EE' },
                  { icon: KeyRound, label: 'Signatures', value: 'ML-DSA + Ed25519' },
                ].map((item) => (
                  <div key={item.label} className="rounded-xl border border-white/10 bg-white/[0.04] p-4">
                    <item.icon className="h-5 w-5 text-cyan-300" />
                    <div className="mt-2 font-mono text-[10px] uppercase tracking-widest text-slate-400">{item.label}</div>
                    <div className="font-mono text-xs font-bold text-white">{item.value}</div>
                  </div>
                ))}
              </div>
              <div className="mt-5 flex items-center justify-between rounded-xl border border-gold/30 bg-gold/[0.06] px-4 py-3">
                <span className="font-mono text-[10px] uppercase tracking-widest text-gold">Zero-Knowledge Relay</span>
                <ShieldCheck className="h-4 w-4 text-gold" />
              </div>
            </div>
          </Reveal>
        </div>
      </section>

      {/* Two product spotlights */}
      <section className="mx-auto max-w-[88rem] space-y-8 px-6 py-12">
        <ProductSpotlight
          to="/qguard-messaging/secure-chat"
          eyebrow="Secure Chat"
          icon={MessageSquareLock}
          title="Conversations the quantum era can't crack"
          blurb="End-to-end encrypted messages, voice & video calls, and file sharing — with disappearing messages, multi-device trust, and one-tap call verification."
          bullets={[
            'Post-quantum, per-message key agreement with forward secrecy',
            'Encrypted attachments, voice notes, and quantum-safe calls',
            'Disappearing, view-once, read-once & time-locked messages',
            'Device approval by QR, revocation, and key-change alerts',
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
            'On-device AES-256-GCM with post-quantum key protection',
            'Tamper- and truncation-proof, any file or folder size',
            'Quantum-safe offline recovery key for new devices',
            'Enterprise & hybrid dual-control recovery for teams',
          ]}
          image="/helix-features/QuantumVault3.png"
          reverse
        />
      </section>

      {/* Combined features */}
      <section className="mx-auto max-w-[88rem] px-6 py-16">
        <SectionHeading
          kicker="Why QGuard Messaging"
          title={<>Enterprise-grade, <Highlight>quantum-safe</Highlight> by design</>}
          subtitle="Both products share the same hardened cryptographic foundation — verified against NIST standards."
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
          ML-KEM is used for key encapsulation only — it protects the keys that protect your data. AES-256-GCM encrypts the content.
        </p>
      </section>

      {/* Quick links band */}
      <section className="mx-auto max-w-[88rem] px-6 py-8">
        <div className="grid gap-5 sm:grid-cols-2">
          {[
            { to: '/qguard-messaging/secure-chat', icon: MessageSquareLock, title: 'Secure Chat', body: 'Messaging, calls & files — quantum-safe and end-to-end encrypted.' },
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
        body="Start using QGuard Messaging — end-to-end encrypted chat and an on-device quantum vault, with nothing for us to read or leak."
        primary={{ label: 'Launch the App', href: '/login' }}
        secondary={{ label: 'View Quantum Vault', to: '/qguard-messaging/quantum-vault' }}
      />
    </MessagingLayout>
  );
}
