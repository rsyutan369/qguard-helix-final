/**
 * QGuard Quantum Vault — marketing page (/qguard-messaging/quantum-vault)
 * Content sourced from docs/quantum-vault/quantum-vault-marketing-copy.md.
 */
import { motion } from 'motion/react';
import {
  Lock,
  HardDrive,
  EyeOff,
  Layers,
  FileCheck2,
  LifeBuoy,
  Building2,
  FolderLock,
  Terminal,
  LockKeyhole,
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

const TRUST = ['NIST FIPS 203', 'FIPS 204 Level 5', '100% On-Device', 'Zero-Knowledge', 'Quantum-Safe Recovery'];

const FEATURES: Feature[] = [
  { icon: Lock, title: 'Post-Quantum Encryption', body: 'Files are sealed with AES-256-GCM and protected by NIST ML-KEM-1024 and ML-DSA-87 (Level 5) — engineered to resist quantum computers.' },
  { icon: HardDrive, title: 'Strictly On-Device', body: "Everything is encrypted and decrypted locally. Your files never touch QGuard's servers — there's nothing to upload, intercept, or leak." },
  { icon: EyeOff, title: 'Zero-Knowledge, Even at Rest', body: 'Your Vault Master Key is itself encrypted by your password. Locked, even your own device holds only ciphertext.' },
  { icon: Layers, title: 'Layered Key Envelope', body: 'A unique key per file, wrapped by your Vault Master Key, sealed with post-quantum cryptography. Breaking one layer never opens your files.' },
  { icon: FileCheck2, title: 'Tamper-Evident', body: 'Every chunk is authenticated and bound to its position, so any change, reorder, or truncation is instantly detected and rejected.' },
  { icon: LifeBuoy, title: 'Quantum-Safe Recovery', body: 'Lose your device? An offline recovery key restores your .qvault files on a brand-new machine — no access to the old one required.' },
  { icon: Building2, title: 'Enterprise Dual-Control', body: 'Optional hybrid recovery requires both a personal key and an enterprise key — two-person integrity for regulated teams.' },
  { icon: FolderLock, title: 'Files & Folders, Any Size', body: 'Encrypt whole folders into a single sealed archive — even the folder structure is hidden inside the ciphertext. Streamed, so size is unlimited.' },
  { icon: Terminal, title: 'Live Crypto Terminal', body: 'Watch the real cryptographic pipeline as it runs — key sealing, signing, and per-chunk progress with true throughput and ETA.' },
  { icon: LockKeyhole, title: 'Zero-Trust Lock', body: 'The Vault opens only with its own password or PIN, and locks automatically when you step away.' },
];

const STEPS = [
  { title: 'Pick a file or folder', body: "It's encrypted on your device with a unique AES-256-GCM key." },
  { title: 'Sealed, quantum-safe', body: 'That key is wrapped with hybrid X25519 + ML-KEM-1024 and the container is signed with ML-DSA-87.' },
  { title: 'Stays with you', body: 'The .qvault file is saved wherever you choose. Nothing is uploaded; only you (or your recovery key) can open it.' },
];

const COMPARISON = [
  ['Where encryption happens', '100% on your device'],
  ['Server access to your files', 'None — files never leave your machine'],
  ['Algorithms', 'ML-KEM-1024 + FIPS 204 Level 5 ML-DSA-87 + AES-256-GCM'],
  ['Key protection at rest', 'Vault Master Key encrypted by your password'],
  ['Integrity', 'Per-chunk tamper + truncation proof'],
  ['File size limit', 'None (streamed)'],
  ['Recovery', 'Offline quantum-safe key; optional enterprise dual-control'],
  ['Harvest-now-decrypt-later resistant', 'Yes'],
];

export default function QuantumVaultPage() {
  return (
    <MessagingLayout>
      {/* Hero */}
      <section className="relative px-6 pb-16 pt-28 sm:pt-32">
        <div className="mx-auto grid max-w-[88rem] items-center gap-12 lg:grid-cols-[1.05fr_0.95fr]">
          <Reveal>
            <Kicker>Quantum Vault</Kicker>
            <h1 className="mt-5 text-4xl font-black leading-[1.05] tracking-tight text-slate-900 sm:text-6xl">
              Your files, sealed for the <Highlight>quantum age</Highlight>.
            </h1>
            <p className="mt-5 max-w-xl text-base leading-relaxed text-slate-600 sm:text-lg">
              Encrypt any file or folder on your device with post-quantum cryptography. Strictly local, zero-knowledge — your data never leaves your machine.
            </p>
            <div className="mt-8 flex flex-wrap items-center gap-3">
              <GoldButton href="/login">Open the Quantum Vault</GoldButton>
              <GhostButton to="/qguard-messaging/secure-chat">See Secure Chat</GhostButton>
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
              <img src="/helix-features/QuantumVault3.png" alt="QGuard Quantum Vault — zero-knowledge vault" className="h-full max-h-[420px] w-full object-cover" />
              <div className="absolute bottom-4 left-4 right-4 z-10 flex items-center justify-between rounded-xl border border-white/15 bg-black/55 px-4 py-2.5 backdrop-blur-md">
                <span className="inline-flex items-center gap-2 font-mono text-[11px] font-bold uppercase tracking-widest text-gold">
                  <Lock className="h-4 w-4" /> ML-KEM-1024 · AES-256-GCM
                </span>
                <span className="font-mono text-[11px] text-cyan-300">On-device</span>
              </div>
            </motion.div>
          </Reveal>
        </div>
      </section>

      {/* Feature grid */}
      <section className="mx-auto max-w-[88rem] px-6 py-16">
        <SectionHeading
          kicker="Advanced Quantum Features"
          title={<>Sealed, <Highlight>quantum-safe</Highlight>, and yours alone</>}
          subtitle="Every capability is verified against the implementation — accurate, not marketing fiction."
        />
        <div className="mt-12 grid gap-5 sm:grid-cols-2 lg:grid-cols-3 xl:grid-cols-5">
          {FEATURES.map((f, i) => (
            <FeatureCard key={f.title} feature={f} delay={(i % 5) * 0.05} />
          ))}
        </div>
      </section>

      {/* How it works */}
      <section className="mx-auto max-w-[88rem] px-6 py-12">
        <SectionHeading kicker="How it works" title="Three steps, fully on-device" />
        <div className="mt-10 grid gap-5 md:grid-cols-3">
          {STEPS.map((s, i) => (
            <StepCard key={s.title} index={i} title={s.title} body={s.body} />
          ))}
        </div>
      </section>

      {/* Comparison */}
      <section className="mx-auto max-w-5xl px-6 py-12">
        <SectionHeading kicker="Why Quantum Vault" title="What you get" center />
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
                <Lock className="h-5 w-5" />
              </span>
              <h2 className="text-xl font-black text-slate-900">About the security</h2>
            </div>
            <p className="mt-4 text-sm leading-relaxed text-slate-600">
              QGuard Quantum Vault is a strictly local, zero-knowledge file vault. Each file is encrypted on your device with
              <strong className="text-slate-900"> AES-256-GCM</strong> under a unique key, which is wrapped by your
              <strong className="text-slate-900"> Vault Master Key</strong> and sealed using hybrid
              <strong className="text-slate-900"> X25519 + ML-KEM-1024</strong> (NIST FIPS 203); every container is dual-signed with
              <strong className="text-slate-900"> ML-DSA-87 + Ed25519</strong> (FIPS 204 Level 5) and key derivation uses
              <strong className="text-slate-900"> HKDF-SHA3-256</strong>. Your Vault Master Key is itself encrypted at rest by your
              password, every chunk is tamper- and truncation-proof, and nothing is ever uploaded to QGuard. A quantum-safe, offline
              recovery key — with optional enterprise dual-control — lets you restore your files on a new device if yours is ever lost.
            </p>
            <p className="mt-4 rounded-xl border border-gold/30 bg-gold/[0.06] px-4 py-3 text-xs leading-relaxed text-slate-600">
              <strong className="text-[#b8860b]">Keep your recovery key safe.</strong> Because the Vault is zero-knowledge, if you lose
              both your device and your recovery key, the files cannot be recovered — by anyone, including QGuard. That is the same
              property that guarantees no one else can read them.
            </p>
          </GlassCard>
        </Reveal>
      </section>

      <CTASection
        title="Lock it down. Quantum-safe."
        body="Encrypt your most sensitive files on your own device with NIST post-quantum cryptography — nothing uploaded, nothing for us to read."
        primary={{ label: 'Open the Quantum Vault', href: '/login' }}
        secondary={{ label: 'Back to Overview', to: '/qguard-messaging' }}
      />
    </MessagingLayout>
  );
}
