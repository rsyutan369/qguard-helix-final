/**
 * QGuard Secure Chat — marketing page (/qguard-messaging/secure-chat)
 * Content sourced from docs/secure-chat/secure-chat-marketing-copy.md.
 */
import { motion } from 'motion/react';
import {
  ShieldCheck,
  Layers,
  Lock,
  EyeOff,
  Clock,
  Paperclip,
  Phone,
  Smartphone,
  KeyRound,
  LockKeyhole,
  MessageSquareLock,
  Check,
} from 'lucide-react';
import {
  MessagingLayout,
  Reveal,
  Highlight,
  Kicker,
  GoldButton,
  GhostButton,
  SectionHeading,
  GlassCard,
  FeatureCard,
  TrustStrip,
  StepCard,
  CTASection,
  type Feature,
} from '../_shared';

const TRUST = ['NIST FIPS 203', 'FIPS 204', 'End-to-End Encrypted', 'Zero-Knowledge', 'Hybrid Post-Quantum'];

const FEATURES: Feature[] = [
  { icon: ShieldCheck, title: 'Post-Quantum by Default', body: 'Every message and call is secured with ML-KEM-1024 and ML-DSA — the NIST-standardized algorithms built to withstand quantum computers.' },
  { icon: Layers, title: 'Hybrid Encryption', body: 'Classical and post-quantum together. An attacker would have to break both — safe even from "harvest now, decrypt later".' },
  { icon: Lock, title: 'True End-to-End', body: "Messages, files, and calls are encrypted on your device and decrypted only on your contact's. The server only ever sees ciphertext." },
  { icon: EyeOff, title: 'Zero-Knowledge', body: 'We store ciphertext and public keys — never your private keys, plaintext, or recovery secrets. QGuard literally cannot read your conversations.' },
  { icon: Clock, title: 'Messages on Your Terms', body: 'Disappearing timers, view-once, read-once, time-locked, edit, and delete — privacy controls built into every message.' },
  { icon: Paperclip, title: 'Encrypted Files & Voice Notes', body: 'Attachments and voice notes are AES-256-GCM encrypted on your device before they ever leave it, with integrity verification on every download.' },
  { icon: Phone, title: 'Quantum-Encrypted Calls', body: '1:1 voice and video with per-frame encryption and a fresh post-quantum key for every call. Verify the call is private in one tap.' },
  { icon: Smartphone, title: 'Device Trust You Control', body: "Approve new devices by QR, see every trusted device, and revoke any instantly. Get alerted if a contact's keys ever change." },
  { icon: KeyRound, title: 'Forward Secrecy', body: 'A fresh key for every single message. Compromising one key never exposes your past or future conversations.' },
  { icon: LockKeyhole, title: 'Zero-Trust Workspace Lock', body: 'Secure Chat has its own password or PIN, separate from your login, with automatic locking when you step away.' },
];

const STEPS = [
  { title: 'Encrypted on your device', body: 'Text, files, and call frames are sealed with AES-256-GCM before they ever leave you.' },
  { title: 'Quantum-safe key exchange', body: 'Keys are agreed using hybrid X25519 + ML-KEM-1024 (NIST FIPS 203), fresh for every message and call.' },
  { title: 'Only your contact can open it', body: 'The relay stores ciphertext only; verify the safety number to confirm no one is in the middle.' },
];

const COMPARISON = [
  ['Encryption', 'End-to-end, hybrid post-quantum'],
  ['Algorithms', 'NIST FIPS 203 ML-KEM-1024 + FIPS 204 ML-DSA'],
  ['Calls', 'Per-frame E2EE + quantum-safe key per call'],
  ['Server access to content', 'None (zero-knowledge)'],
  ['Forward secrecy', 'Yes, per message'],
  ['Disappearing / view-once / time-locked', 'Yes'],
  ['Device verification', 'QR approval, revocation, key-change alerts'],
  ['Harvest-now-decrypt-later resistant', 'Yes'],
];

export default function SecureChatPage() {
  return (
    <MessagingLayout>
      {/* Hero */}
      <section className="relative px-6 pb-16 pt-28 sm:pt-32">
        <div className="mx-auto grid max-w-[88rem] items-center gap-12 lg:grid-cols-[1.05fr_0.95fr]">
          <Reveal>
            <Kicker>Secure Chat</Kicker>
            <h1 className="mt-5 text-4xl font-black leading-[1.05] tracking-tight text-slate-900 sm:text-6xl">
              Conversations the <Highlight>quantum era</Highlight> can't crack.
            </h1>
            <p className="mt-5 max-w-xl text-base leading-relaxed text-slate-600 sm:text-lg">
              End-to-end encrypted messages, calls, and files — protected by NIST post-quantum cryptography. Not even QGuard can read them.
            </p>
            <div className="mt-8 flex flex-wrap items-center gap-3">
              <GoldButton href="/login">Start a secure chat</GoldButton>
              <GhostButton to="/qguard-messaging/quantum-vault">See Quantum Vault</GhostButton>
            </div>
            <div className="mt-8">
              <TrustStrip items={TRUST} />
            </div>
          </Reveal>

          <Reveal delay={0.15}>
            <motion.div
              whileHover={{ scale: 1.01 }}
              transition={{ duration: 0.4 }}
              className="relative overflow-hidden rounded-2xl border-2 border-slate-900 bg-slate-950 shadow-[0_30px_90px_rgba(2,6,23,0.3)]"
            >
              <div className="absolute inset-x-0 top-0 z-10 h-[3px] bg-gradient-to-r from-cyan-400 via-gold to-violet-500" />
              <img src="/Secure_communication.png" alt="QGuard Secure Chat" className="h-full max-h-[420px] w-full object-cover" />
              <div className="absolute bottom-4 left-4 right-4 z-10 flex items-center justify-between rounded-xl border border-white/15 bg-black/55 px-4 py-2.5 backdrop-blur-md">
                <span className="inline-flex items-center gap-2 font-mono text-[11px] font-bold uppercase tracking-widest text-emerald-300">
                  <ShieldCheck className="h-4 w-4" /> Quantum-encrypted
                </span>
                <span className="font-mono text-[11px] text-cyan-300">Verified</span>
              </div>
            </motion.div>
          </Reveal>
        </div>
      </section>

      {/* Feature grid */}
      <section className="mx-auto max-w-[88rem] px-6 py-16">
        <SectionHeading
          kicker="Security & Advanced Features"
          title={<>Built for <Highlight>privacy</Highlight>, end to end</>}
          subtitle="Every capability is verified against the implementation — accurate, not marketing fiction."
        />
        <div className="mt-12 grid gap-5 sm:grid-cols-2 lg:grid-cols-3 xl:grid-cols-5">
          {FEATURES.map((f, i) => (
            <FeatureCard key={f.title} feature={f} delay={(i % 5) * 0.05} />
          ))}
        </div>
      </section>

      {/* How it's protected */}
      <section className="mx-auto max-w-[88rem] px-6 py-12">
        <SectionHeading kicker="How it's protected" title="Three steps, end to end" />
        <div className="mt-10 grid gap-5 md:grid-cols-3">
          {STEPS.map((s, i) => (
            <StepCard key={s.title} index={i} title={s.title} body={s.body} />
          ))}
        </div>
      </section>

      {/* Comparison */}
      <section className="mx-auto max-w-5xl px-6 py-12">
        <SectionHeading kicker="Why QGuard" title="What you get" center />
        <Reveal>
          <GlassCard className="mt-10 overflow-hidden" hover={false}>
            <ul className="divide-y divide-slate-200">
              {COMPARISON.map(([k, v]) => (
                <li key={k} className="flex flex-col gap-1 px-6 py-4 sm:flex-row sm:items-center sm:justify-between">
                  <span className="text-sm font-semibold text-slate-900">{k}</span>
                  <span className="inline-flex items-center gap-2 text-sm text-slate-600">
                    <Check className="h-4 w-4 shrink-0 text-gold" /> {v}
                  </span>
                </li>
              ))}
            </ul>
          </GlassCard>
        </Reveal>
      </section>

      {/* About */}
      <section className="mx-auto max-w-4xl px-6 py-10">
        <Reveal>
          <GlassCard className="p-8 sm:p-10" hover={false}>
            <div className="flex items-center gap-3">
              <span className="flex h-11 w-11 items-center justify-center rounded-xl border border-gold/30 bg-gold/10 text-[#b8860b]">
                <MessageSquareLock className="h-5 w-5" />
              </span>
              <h2 className="text-xl font-black text-slate-900">About the security</h2>
            </div>
            <p className="mt-4 text-sm leading-relaxed text-slate-600">
              QGuard Secure Chat is end-to-end encrypted with hybrid post-quantum cryptography: key exchange uses
              <strong className="text-slate-900"> ML-KEM-1024 + X25519</strong> (NIST FIPS 203), identity and messages are
              <strong className="text-slate-900"> dual-signed with ML-DSA + Ed25519</strong> (FIPS 204), and content is sealed with
              <strong className="text-slate-900"> AES-256-GCM</strong> keyed via <strong className="text-slate-900">HKDF-SHA3-256</strong>.
              Every message uses a fresh key (forward secrecy), is authenticated and replay-protected, and is decrypted only on your
              device. Voice and video calls add per-frame end-to-end encryption with one-tap safety-number verification. Private keys
              never leave your device, and the server operates zero-knowledge — it can never read your messages, files, or calls.
            </p>
          </GlassCard>
        </Reveal>
      </section>

      <CTASection
        title="Talk freely. Stay private."
        body="Start an end-to-end encrypted conversation protected by NIST post-quantum cryptography — verify the safety number and no one in the middle, not even QGuard, can read it."
        primary={{ label: 'Launch the App', href: '/login' }}
        secondary={{ label: 'Back to Overview', to: '/qguard-messaging' }}
      />
    </MessagingLayout>
  );
}
