/**
 * QGuard Quantum Vault — marketing page (/qguard-messaging/quantum-vault)
 * Content sourced from qguard-messaging/CHANGELOG.md, the vault source and
 * docs/security-limitations.md. The interactive stages are illustrations of
 * mechanisms the vault implements, not a working vault.
 */
import { Check, Lock } from 'lucide-react';
import {
  MessagingLayout,
  Reveal,
  Highlight,
  Kicker,
  GoldButton,
  GhostButton,
  SectionHeading,
  GlassCard,
  TrustStrip,
  StepCard,
  CTASection,
  DownloadButton,
} from '../_shared';
import { Aurora, StageFrame } from '../_motion';
import { HeroVaultScene } from '../_scenes-hero';
import { ChunkIntegrityLab, CryptoTerminal, EnvelopeLayers, RecoveryKeys } from '../_scenes-vault';
import { Block, FeatureAtlas, StraightTalk, type Limit } from '../_catalog';

const TRUST = ['NIST FIPS 203', 'FIPS 204 Level 5', '100% On-Device', 'Zero-Knowledge', 'Quantum-Safe Recovery'];

const STEPS = [
  { title: 'Pick a file or folder', body: "It's encrypted on your device with a unique AES-256-GCM key, streamed in authenticated chunks." },
  { title: 'Sealed, quantum-safe', body: 'That key is wrapped under your PIN-bound vault key (AES-256-GCM) and the container is signed with ML-DSA-87 + Ed25519. Sharing to a person or enterprise recovery adds a hybrid X25519 + ML-KEM-1024 seal.' },
  { title: 'Stays with you', body: 'The .qvault file is saved wherever you choose. Nothing is uploaded; only you (or your recovery key) can open it.' },
];

const SHARE_STEPS = [
  { title: 'Create a Portable Hybrid Identity', body: 'Four keypairs — X25519 + ML-KEM-1024 for encryption, Ed25519 + ML-DSA-87 for signing — kept in a .qgkey sealed under your passphrase (Argon2id, 64 MiB).' },
  { title: 'Hand out only the public bundle', body: 'The .qgpub.json holds public keys and nothing else. Anyone with it can seal a file to you; nobody can open it without your private bundle.' },
  { title: 'Seal to a person, not a device', body: 'The recipient never holds your device key or Vault Master Key, and the container records who sealed it with a post-quantum signature.' },
];

const COMPARISON = [
  ['Where encryption happens', '100% on your device'],
  ['Server access to your files', 'None — files never leave your machine'],
  ['Algorithms', 'AES-256-GCM · ML-DSA-87 + Ed25519 · ML-KEM-1024 + X25519 for sharing and enterprise recovery'],
  ['Vault lock', 'PIN-bound in the cryptography (.qvault v5), not just the interface'],
  ['Key protection at rest', 'Vault Master Key encrypted by your password (Argon2id)'],
  ['Integrity', 'Every chunk checked — tampering, reordering and truncation are detected'],
  ['File size limit', 'None set by the app (streamed)'],
  ['Sharing', 'Seal to a person with a Portable Hybrid Identity'],
  ['Recovery', 'Offline quantum-safe key; optional enterprise dual-control'],
  ['Harvest-now-decrypt-later resistant', 'Designed to resist — keys are protected by AES-256 or hybrid ML-KEM-1024, never classical-only'],
];

const VAULT_LIMITS: Limit[] = [
  { title: 'Lose the device and the recovery key, lose the files', body: 'Because the vault is zero-knowledge, nobody can recover it for you — including QGuard. That is the same property that stops anyone else reading it. Keep the recovery key offline and safe.' },
  { title: 'Older containers are not PIN-bound until you re-protect them', body: 'Containers made before .qvault v5 stay readable and are reported as not PIN-bound; “re-protect” rewrites their header. New containers are PIN-bound.' },
  { title: 'Whole-folder vaults are desktop-only', body: 'Android cannot walk a directory tree through the Storage Access Framework, so it seals individual files.' },
  { title: 'Not independently audited', body: 'The implementation is production-oriented but no outside party has audited it. Secure deletion cannot be guaranteed on every SSD, and malware on an unlocked device can read what you open.' },
  { title: 'Updates are signed with Ed25519', body: 'The installer’s auto-update signature is Ed25519 (minisign) — the updater has no post-quantum option. The verification key ships inside the installed app.' },
];

export default function QuantumVaultPage() {
  return (
    <MessagingLayout>
      {/* Hero */}
      <section className="relative px-6 pb-16 pt-28 sm:pt-32">
        <Aurora />
        <div className="mx-auto grid max-w-[88rem] items-center gap-12 grid-cols-[minmax(0,1fr)] lg:grid-cols-2">
          <Reveal>
            <Kicker>Quantum Vault</Kicker>
            <h1 className="mt-5 text-4xl font-black leading-[1.05] tracking-tight text-slate-900 sm:text-6xl">
              Your files, sealed for the <Highlight>quantum age</Highlight>.
            </h1>
            <p className="mt-5 max-w-xl text-base leading-relaxed text-slate-600 sm:text-lg">
              Encrypt any file — or, on desktop, a whole folder — on your device with post-quantum cryptography. Strictly local, zero-knowledge, and locked by your PIN in the cryptography itself — your data never leaves your machine.
            </p>
            <div className="mt-8 flex flex-wrap items-center gap-3">
              <DownloadButton />
              <GoldButton href="/login">Open the Quantum Vault</GoldButton>
              <GhostButton to="/qguard-messaging/secure-chat">See Secure Chat</GhostButton>
            </div>
            <div className="mt-8">
              <TrustStrip items={TRUST} />
            </div>
          </Reveal>

          <Reveal delay={0.15}>
            <StageFrame
              title="Quantum Vault // sealed"
              bodyClassName="!px-2 !py-2"
              note={
                <>
                  <span className="inline-flex items-center gap-2"><span className="qm-live-dot" aria-hidden />Encrypted on this device. Nothing is uploaded.</span>
                  <span>Move your pointer over the scene.</span>
                </>
              }
            >
              <HeroVaultScene />
            </StageFrame>
          </Reveal>
        </div>
      </section>

      {/* Feature atlas */}
      <section className="relative mx-auto max-w-[88rem] px-6 py-16">
        <SectionHeading
          kicker="Advanced Quantum Features"
          title={<>Sealed, <Highlight>quantum-safe</Highlight>, and yours alone</>}
          subtitle="Every capability is checked against the implementation. Filter by what you care about."
        />
        <FeatureAtlas product="vault" />
      </section>

      {/* Envelope */}
      <Block
        kicker="Layer by layer"
        title={<>A key envelope in <Highlight>five layers</Highlight></>}
        subtitle="Drag the slider to pull the container apart, and click a layer to see what it does and what it stops. The hybrid post-quantum seal is added when you share a file or use enterprise recovery."
      >
        <Reveal><EnvelopeLayers /></Reveal>
      </Block>

      {/* Integrity */}
      <Block
        kicker="Tamper-evident"
        title={<>Change one bit and <Highlight>the vault says no</Highlight></>}
        subtitle="Flip a chunk, swap two, or cut the end off — each attack is a different failure, and each is refused before anything is written."
      >
        <Reveal><ChunkIntegrityLab /></Reveal>
      </Block>

      {/* How it works + terminal */}
      <section className="mx-auto max-w-[88rem] px-6 py-12">
        <SectionHeading kicker="How it works" title="Three steps, fully on-device" />
        <div className="mt-10 grid gap-5 md:grid-cols-3">
          {STEPS.map((s, i) => (
            <StepCard key={s.title} index={i} title={s.title} body={s.body} />
          ))}
        </div>
        <div className="mt-8">
          <Reveal><CryptoTerminal /></Reveal>
        </div>
      </section>

      {/* Sharing */}
      <Block
        kicker="Share without sharing keys"
        title={<>Seal a file to <Highlight>a person</Highlight></>}
        subtitle="A Portable Hybrid Identity lets someone send you a quantum-encrypted file — or you, them — without either side ever holding the other’s device key."
      >
        <div className="grid gap-5 md:grid-cols-3">
          {SHARE_STEPS.map((s, i) => (
            <StepCard key={s.title} index={i} title={s.title} body={s.body} />
          ))}
        </div>
      </Block>

      {/* Recovery */}
      <Block
        kicker="Recovery"
        title={<>Restore on a new machine — <Highlight>with the right keys</Highlight></>}
        subtitle="Choose personal, enterprise or hybrid dual-control recovery. Try it: present the keys and see when the vault opens."
      >
        <Reveal><RecoveryKeys /></Reveal>
      </Block>

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

      {/* Straight talk */}
      <Block narrow kicker="Straight talk" title={<>Where the guarantees <Highlight>stop</Highlight></>} subtitle="What a careful reviewer would ask us.">
        <Reveal><StraightTalk items={VAULT_LIMITS} /></Reveal>
      </Block>

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
              <strong className="text-slate-900"> AES-256-GCM</strong> under a unique key, which is wrapped by your PIN-bound
              <strong className="text-slate-900"> Vault Master Key</strong>; files you share to a person, and enterprise recovery, add a hybrid
              <strong className="text-slate-900"> X25519 + ML-KEM-1024</strong> seal (NIST FIPS 203). Every container is dual-signed with
              <strong className="text-slate-900"> ML-DSA-87 + Ed25519</strong> (FIPS 204 Level 5) and key derivation uses
              <strong className="text-slate-900"> HKDF-SHA3-256</strong>. Your Vault Master Key is itself encrypted at rest by your
              password, every chunk is tamper-evident (any change, reorder or truncation is detected and refused), and nothing is ever uploaded to QGuard. A quantum-safe, offline
              recovery key — with optional enterprise dual-control — lets you restore your files on a new device if yours is ever lost.
            </p>
            <p className="mt-4 rounded-xl border border-gold/30 bg-gold/[0.06] px-4 py-3 text-xs leading-relaxed text-slate-600">
              <strong className="text-[#b8860b]">Keep your recovery key safe.</strong> Because the Vault is zero-knowledge, if you lose
              both your device and your recovery key, the files cannot be recovered — by anyone, including QGuard. That is the same
              property that stops anyone else reading them.
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
