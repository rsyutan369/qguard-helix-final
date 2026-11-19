/**
 * QGuard Quantum Vault — marketing page (/qguard-messaging/quantum-vault)
 * Content sourced from qguard-messaging/CHANGELOG.md, the vault source and
 * docs/security-limitations.md; the Vault Storage line (storage, backup,
 * library, sharing, pattern unlock, hidden vaults) from the CHANGELOG
 * and docs/QUANTUM_VAULT_STORAGE.md.
 * The interactive stages are illustrations of mechanisms the vault
 * implements, not a working vault.
 */
import { Check, Lock } from 'lucide-react';
import { MessagingBuildScope, SecurityCoverage } from '../_security-coverage';
import {
  MessagingLayout,
  Reveal,
  Highlight,
  Kicker,
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
import { LocalWorkflowLink, LocalWorkflows } from '../_local-workflows';
import { ChunkIntegrityLab, CryptoTerminal, EnvelopeLayers, RecoveryKeys } from '../_scenes-vault';
import { HiddenVaultLab, PatternLab, StorageLibraryLab } from '../_scenes-vault-storage';
import { Block, FeatureAtlas, StraightTalk, VaultNewGrid, type Limit } from '../_catalog';
import { Tag } from '../_motion';

const TRUST = ['AES-256-GCM', 'On-Device by Default', 'Signed Standard Containers'];

const BACKUP_STEPS = [
  { title: 'Turn on encrypted backup', body: 'Off by default. Security & Backup → Encrypted cloud backup needs a personal recovery key, so a backup never depends on one device. Each encrypted container goes up in 8 MiB parts, resuming after interruptions.' },
  { title: 'One library on every approved device', body: 'Devices you approved in the Device Trust Center share one library: files, folders, renames, Trash and deletes. Files from other devices download and are verified when you first open them. Publishing never overwrites another device’s newer change.' },
  { title: 'Restore with your recovery key', body: 'After signing in on the new device, Restore from backup uses your personal recovery key, verifies the download and re-binds each file to the new vault.' },
];

const QUOTAS: Array<[string, string]> = [
  ['Starter', 'Local only'],
  ['Basic', '2 GiB'],
  ['Pro', '10 GiB'],
  ['Elite', '100 GiB'],
];

const SHARE_USER_STEPS = [
  { title: 'Pick people and a permission', body: 'Share on any file: choose QGuard contacts, view only or view and save, and an optional expiry. Backup does not need to be on — a file without a cloud copy gets one for the share, removed again when no share uses it.' },
  { title: 'One envelope per recipient device', body: 'Everyone downloads the same encrypted copy. Each recipient device gets its own key envelope sealed with X25519 + ML-KEM-1024 and signed by your device with Ed25519 + ML-DSA-65, which the recipient checks before opening.' },
  { title: 'Accept, preview, save — or revoke', body: 'Recipients accept or decline, preview in memory, or save their own re-sealed copy. Shared by me shows who accepted and the access history; revoke per person or for everyone. People who blocked you are left out without being told.' },
];

const STEPS = [
  { title: 'Pick a file, or a folder on desktop', body: "It's encrypted on your device with a unique AES-256-GCM key, streamed in authenticated chunks." },
  { title: 'Wrap the file key and sign the header', body: 'For standard local .qvault v5 files, the vault master key wraps the file key, and Ed25519 + ML-DSA-87 signs the header. Portable recipient sealing and enterprise recovery use a hybrid X25519 + ML-KEM-1024 envelope.' },
  { title: 'Stays with you', body: 'Save a .qvault file locally or import it into the encrypted library. The app uploads encrypted content when you choose cloud backup or in-app sharing.' },
];

const SHARE_STEPS = [
  { title: 'Create a Portable Hybrid Identity', body: 'Four keypairs — X25519 + ML-KEM-1024 for key establishment, Ed25519 + ML-DSA-87 for signing — kept in a .qgkey sealed under your passphrase (Argon2id, 64 MiB).' },
  { title: 'Hand out only the public bundle', body: 'The .qgpub.json holds public keys and nothing else. Anyone with it can seal a file to you; nobody can open it without your private bundle.' },
  { title: 'Seal to a person, not a device', body: 'The recipient never holds your device key or Vault Master Key, and the container records who sealed it with a post-quantum signature.' },
];

const COMPARISON = [
  ['Where encryption happens', '100% on your device'],
  ['Server access to your files', 'Cloud backup and in-app sharing upload ciphertext and service metadata, such as IDs and file sizes'],
  ['Algorithms', 'Standard .qvault v5: AES-256-GCM and Ed25519 + ML-DSA-87; hybrid key wraps for recipient sealing or enterprise recovery'],
  ['Vault lock', 'Standard v5 file keys are wrapped under the vault master key, which is protected by the configured unlock methods'],
  ['Unlock', 'Password, PIN or a drawn 4 × 4 pattern'],
  ['Key protection at rest', 'Vault Master Key encrypted by your password (Argon2id)'],
  ['File names and types', 'Sealed in an encrypted index — containers carry neither'],
  ['Integrity', 'Every chunk checked — tampering, reordering and truncation are detected'],
  ['File size limit', 'Local tools stream chunks; storage, device and cloud limits still apply'],
  ['Sharing', 'Seal to a person with a Portable Hybrid Identity, or share to QGuard users with expiry and revoke'],
  ['Recovery', 'Offline quantum-safe key; optional enterprise dual-control; restore from encrypted backup'],
  ['Hidden local storage', 'Hidden vaults the app never lists'],
  ['Hidden Vault recovery', 'Optional 12-word phrase can reset the pattern if the local vault files still exist'],
];

const VAULT_LIMITS: Limit[] = [
  { title: 'Recovery needs encrypted files and the configured keys', body: 'Keep both an encrypted copy of your files and the required recovery key or keys. A key cannot recreate missing files. Hidden vaults use their own optional local recovery phrase.' },
  { title: 'Older containers are not PIN-bound until you re-protect them', body: 'Containers made before .qvault v5 stay readable and are reported as not PIN-bound; “re-protect” rewrites their header. New containers are PIN-bound.' },
  { title: 'Whole-folder vaults are desktop-only', body: 'Messaging Vault Tools seal individual files on Android. The Vault Storage library can import multiple files and export one file at a time.' },
  { title: 'Cloud backup is opt-in, and the server still sees sizes', body: 'With backup on, the server holds ciphertext plus random ids, sizes, hashes of the ciphertext and which of your devices uploaded — never names or content. A malicious server could serve an older folder list than the newest one; every file it serves must still authenticate. Backup needs a personal recovery key and a plan with cloud storage.' },
  { title: 'Revoking a share cannot take back a copy', body: 'Revoking stops further downloads, not a copy already saved or a file already opened. View only is enforced by the app, not by cryptography, and “opened” / “saved” in the access history are reported by the recipient’s app.' },
  { title: 'A hidden vault hides its contents, not that the folder exists', body: 'An examiner can see the pool folder’s size and file count (every account has one, with cover files), and comparing two images shows it changed. Flash storage can keep stale blocks of overwritten ciphertext. There is no hidden-vault backup or sharing. If you set one up, its own 12-word phrase can reset the pattern while the local files remain.' },
  { title: 'A pattern is only as strong as its dots', body: 'Someone who extracts this device’s secure-store key can try patterns offline at Argon2id cost each, so a short or common pattern is guessable — use 8 or more dots. The source also defines a restricted build mode that disables pattern unlock; that setting is not a FIPS validation claim.' },
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
              Encrypt files locally with AES-256-GCM, or seal a whole folder on desktop. Standard containers have post-quantum signatures. Hidden vaults use a separate local format.
            </p>
            <p className="mt-4 flex max-w-xl flex-wrap items-center gap-2 border-l-2 border-gold pl-4 text-sm leading-relaxed text-slate-700">
              <Tag kind="ready">In reviewed source</Tag>
              <span>Vault Storage, encrypted backup across your devices, sharing, draw-pattern unlock and hidden vaults.</span>
            </p>
            <MessagingBuildScope />
            <div className="mt-8 flex flex-wrap items-center gap-3">
              <DownloadButton />
              <GhostButton to="/qguard-messaging/secure-chat">See Secure Chat</GhostButton>
              <LocalWorkflowLink>See how XFER imports into Vault</LocalWorkflowLink>
            </div>
            <div className="mt-8">
              <TrustStrip items={TRUST} />
            </div>
          </Reveal>

          <Reveal delay={0.15}>
            <StageFrame
              title="Quantum Vault illustration"
              bodyClassName="!px-2 !py-2"
              note={
                <>
                  <span className="inline-flex items-center gap-2"><span className="qm-live-dot" aria-hidden />Encryption happens on the device. Cloud backup and in-app sharing can upload ciphertext.</span>
                  <span>Move your pointer over the scene.</span>
                </>
              }
            >
              <HeroVaultScene />
            </StageFrame>
          </Reveal>
        </div>
      </section>

      <LocalWorkflows page="vault" />

      {/* New in the vault */}
      <Block
        kicker="New in the Quantum Vault"
        title={<>A vault that <Highlight>keeps your files</Highlight> — and can keep a secret</>}
        subtitle="The standard library uses signed .qvault v5 containers. Hidden vaults use a separate encryption format and recovery method."
      >
        <VaultNewGrid />
      </Block>

      {/* Vault Storage */}
      <Block
        kicker="Vault Storage"
        title={<>Your library, with <Highlight>names and contents sealed</Highlight> on disk</>}
        subtitle="Folders, categories, favourites, Trash, search and previews for you. For anyone reading the disk: containers with no name or type, and one sealed index. Switch views and try the permanent-delete illustration. It shows key removal; it does not prove physical erasure."
      >
        <Reveal><StorageLibraryLab /></Reveal>
      </Block>

      {/* Pattern unlock */}
      <Block
        kicker="Draw to unlock"
        title={<>A pattern, sealed <Highlight>exactly like a PIN</Highlight></>}
        subtitle="Connect at least six dots on a 4 × 4 grid. The pattern is stretched with Argon2id and unwraps the Vault Master Key — with the same attempt limits as the PIN."
      >
        <Reveal><PatternLab /></Reveal>
      </Block>

      {/* Hidden vaults */}
      <Block
        kicker="Hidden vaults"
        title={<>A separate vault with <Highlight>private access</Highlight></>}
        subtitle="Create it inside your unlocked vault and open it with its own pattern. Set up the optional 12-word phrase if you want a way to reset that pattern on the local files."
      >
        <Reveal><HiddenVaultLab /></Reveal>
      </Block>

      {/* Backup + devices */}
      <Block
        kicker="Encrypted backup · one library"
        title={<>Back up ciphertext. <Highlight>Restore with your key</Highlight>.</>}
        subtitle="Opt-in. The server stores encrypted containers it cannot open; restoring requires both access to the backed-up ciphertext and your recovery key."
      >
        <div className="grid gap-5 md:grid-cols-3">
          {BACKUP_STEPS.map((s, i) => (
            <StepCard key={s.title} index={i} title={s.title} body={s.body} />
          ))}
        </div>
        <Reveal>
          <GlassCard className="mt-6 p-5" hover={false}>
            <div className="flex flex-wrap items-center justify-between gap-3">
              <span className="font-mono text-[11px] font-bold uppercase tracking-[0.2em] text-slate-500">Backup storage by plan</span>
              <span className="text-xs text-slate-500">Default quotas in the backup migration. The server enforces your account’s current quota; a lapsed plan pauses new uploads.</span>
            </div>
            <div className="mt-4 grid grid-cols-2 gap-3 sm:grid-cols-4">
              {QUOTAS.map(([plan, quota]) => (
                <div key={plan} className="rounded-xl border border-slate-200 bg-white px-4 py-3 text-center">
                  <div className="text-xs font-semibold text-slate-500">{plan}</div>
                  <div className="mt-1 text-lg font-black text-slate-900">{quota}</div>
                </div>
              ))}
            </div>
          </GlassCard>
        </Reveal>
      </Block>

      {/* Sharing with QGuard users */}
      <Block
        kicker="Share inside QGuard"
        title={<>Share a file with <Highlight>people, not passwords</Highlight></>}
        subtitle="One encrypted copy, a separate post-quantum key envelope for every recipient device, and a revoke button."
      >
        <div className="grid gap-5 md:grid-cols-3">
          {SHARE_USER_STEPS.map((s, i) => (
            <StepCard key={s.title} index={i} title={s.title} body={s.body} />
          ))}
        </div>
      </Block>

      {/* Feature atlas */}
      <section className="relative mx-auto max-w-[88rem] px-6 py-16">
        <SectionHeading
          kicker="Advanced Quantum Features"
          title={<>How Vault <Highlight>protects files and keys</Highlight></>}
          subtitle="Every capability is checked against the implementation. Filter by what you care about."
        />
        <FeatureAtlas product="vault" />
      </section>

      {/* Envelope */}
      <Block
        kicker="Layer by layer"
        title={<>A key envelope in <Highlight>five layers</Highlight></>}
        subtitle="Drag the slider to pull the container apart, and click a layer to see what it does and what it stops. This illustrates the standard container. Portable recipient sealing and enterprise recovery add a hybrid post-quantum key wrap."
      >
        <Reveal><EnvelopeLayers /></Reveal>
      </Block>

      {/* Integrity */}
      <Block
        kicker="Tamper-evident"
        title={<>Change one bit and <Highlight>the vault says no</Highlight></>}
        subtitle="Try changing, reordering or truncating chunks in the illustration. Authentication or format checks must pass for a file to be reported as successfully decrypted."
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
        kicker="Share outside the app"
        title={<>Seal a file to <Highlight>a person</Highlight></>}
        subtitle="Available today under Encrypt & Decrypt Tools: a Portable Hybrid Identity lets someone send you a quantum-encrypted file — or you, them — without either side ever holding the other’s device key."
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

      <Block kicker="Security by workflow" title={<>What protects <Highlight>Vault and local transfers</Highlight></>}>
        <Reveal><SecurityCoverage area="vault" /></Reveal>
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
              Standard Vault files use a separate AES-256-GCM key for each file and authenticate chunks as they are read. The signed header binds the key wraps to the file. Cloud backup and in-app sharing upload ciphertext and operational metadata. Local access, personal recovery, enterprise recovery and recipient sharing each use their own key wrap.
            </p>
            <p className="mt-4 text-sm leading-relaxed text-slate-600">
              <strong className="text-slate-900">Vault Storage</strong> seals file names and types in an AES-256-GCM index derived
              from your vault key, a <strong className="text-slate-900">drawn pattern</strong> can unlock the vault (Argon2id, 64 MiB), and
              <strong className="text-slate-900"> hidden vaults</strong> keep a second library that opens only with its own pattern on this device.
            </p>
            <p className="mt-4 rounded-xl border border-gold/30 bg-gold/[0.06] px-4 py-3 text-xs leading-relaxed text-slate-600">
              <strong className="text-[#b8860b]">Keep an encrypted copy and the required recovery keys.</strong> An account login does not decrypt a vault. A Hidden Vault recovery phrase can recover local access only if the hidden vault files still exist.
            </p>
          </GlassCard>
        </Reveal>
      </section>

      <CTASection
        title="Protect files on your device"
        body="Install QGuard Messaging to open its local Vault. For recoverable files, keep an encrypted copy and the applicable recovery keys."
        secondary={{ label: 'Back to Overview', to: '/qguard-messaging' }}
      />
    </MessagingLayout>
  );
}
