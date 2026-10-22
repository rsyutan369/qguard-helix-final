/**
 * Feature catalogue + overview sections for the QGuard Messaging pages.
 *
 * Source of truth for every claim below: qguard-messaging/CHANGELOG.md,
 * docs/security-limitations.md and
 * docs/superpowers/plans/2026-10-16-feature-roadmap.md. Where something is
 * opt-in, platform-limited, unreviewed or only designed, it carries a tag that
 * says so — the pages must never promise more than the app does.
 */
import React, { useState } from 'react';
import { AnimatePresence, motion } from 'motion/react';
import {
  Bot,
  Building2,
  ChevronDown,
  Check,
  Fingerprint,
  FolderLock,
  History,
  KeyRound,
  Layers,
  LifeBuoy,
  Lock,
  Minus,
  Phone,
  Radio,
  RefreshCcw,
  Search,
  ShieldCheck,
  Users,
  WifiOff,
  type LucideIcon,
} from 'lucide-react';
import { cn } from '@/lib/utils';
import { GlassCard, MESSAGING_INSTALLER, SectionHeading } from './_shared';
import { CountUp, Rise, Tag, TiltCard, useCalm, type TagKind } from './_motion';

/* ------------------------------------------------------------- atlas -------- */

export type Category = 'protect' | 'verify' | 'connect' | 'recover' | 'resilience' | 'enterprise' | 'vault';

export type AtlasItem = {
  icon: LucideIcon;
  title: string;
  body: string;
  category: Category;
  tags: TagKind[];
  since: string;
  /** Where the page that shows this feature is — chat, vault, or the whole app. */
  product: 'chat' | 'vault' | 'both';
};

export const CATEGORY_LABEL: Record<Category | 'all', string> = {
  all: 'Everything',
  protect: 'Protect',
  verify: 'Verify',
  connect: 'Connect',
  recover: 'Recover',
  resilience: 'Resilience',
  enterprise: 'Enterprise',
  vault: 'Vault',
};

export const ATLAS: AtlasItem[] = [
  { icon: ShieldCheck, title: 'Conversation protection badge', body: 'Says Quantum-safe, Needs attention or Not measured yet — and lists the evidence: which devices the next message is sealed to, the hybrid form, pinned keys and forward-secrecy state.', category: 'protect', tags: ['ready'], since: '1.4.0', product: 'chat' },
  { icon: RefreshCcw, title: 'Post-quantum session ratchet', body: 'A key per message, deleted once used, with a fresh ML-KEM-1024 exchange at least every 50 messages or 24 hours. Opt-in, and not yet independently reviewed.', category: 'protect', tags: ['optin'], since: '1.4.0', product: 'chat' },
  { icon: Fingerprint, title: 'Device pins', body: 'The relay is only a directory, so this device keeps its own record of whose devices are whose. A device it invented is new — nothing is sealed to it until you approve it.', category: 'protect', tags: ['ready'], since: '1.3.11', product: 'chat' },
  { icon: Layers, title: 'Transcript-bound hybrid KEM', body: 'The X25519 key, the recipient key and a hash of the ML-KEM ciphertext are mixed through HKDF-SHA3-256, and a non-contributory X25519 result is refused.', category: 'protect', tags: ['ready'], since: '1.3.11', product: 'both' },
  { icon: Lock, title: 'SHA-3 where it was missing', body: 'MFA recovery codes, attachment checksums and the lock verifier moved to SHA3-256 / Argon2id. Three SHA-256 uses remain on purpose and are listed openly.', category: 'protect', tags: ['ready'], since: '1.4.0', product: 'both' },
  { icon: ShieldCheck, title: 'A hardening report that is measured', body: 'Post-quantum protection, secure memory and rate limiting are the outcome of a start-up self-test of the primitives in this binary — not constants.', category: 'protect', tags: ['ready'], since: '1.3.11', product: 'both' },

  { icon: Lock, title: 'Messages on your terms', body: 'Disappearing timers, view-once, read-once, time-locked, edit and delete. Anything armed stays visible in the composer — a burn-on-read you cannot see would be a trap.', category: 'protect', tags: ['ready'], since: '', product: 'chat' },
  { icon: Layers, title: 'Encrypted files & voice notes', body: 'AES-256-GCM on your device before anything leaves it, bound to its container, with integrity verification on every download (SHA3-256 checksum on current builds).', category: 'protect', tags: ['ready'], since: '', product: 'chat' },
  { icon: Lock, title: 'Zero-trust workspace locks', body: 'Secure Chat and Quantum Vault each have their own password or PIN (Argon2id), separate from your login, with automatic locking when you step away.', category: 'protect', tags: ['ready'], since: '', product: 'both' },

  { icon: Fingerprint, title: 'Verify a contact', body: 'Compare a safety number built from both devices’ keys, mark it verified, and your two apps pair automatically over a post-quantum, signed exchange.', category: 'verify', tags: ['ready'], since: '1.4.0', product: 'chat' },
  { icon: Phone, title: 'Call phrase', body: 'Four words only your two paired devices can produce for that call. Compare them aloud; nothing is sent, so nothing can be copied or replayed into another call.', category: 'verify', tags: ['ready'], since: '1.4.0', product: 'chat' },
  { icon: Phone, title: 'Per-call keys, authenticated caller', body: 'The media key depends on a key pair that exists only for that call, and the caller signs it with its registered identity. A signature that fails ends the call.', category: 'verify', tags: ['ready'], since: '1.3.11', product: 'chat' },

  { icon: Users, title: 'Group chats', body: 'End-to-end encrypted groups of up to 32 people. Every message is sealed to each member’s devices — no shared group key to leak. The group name travels encrypted.', category: 'connect', tags: ['ready'], since: '1.4.0', product: 'chat' },
  { icon: Phone, title: 'Group video calls', body: 'Up to three people. Each pair gets its own separately encrypted link with its own hybrid ML-KEM key. Screen sharing is on desktop, video only.', category: 'connect', tags: ['ready', 'desktop'], since: '1.4.0', product: 'chat' },
  { icon: Radio, title: 'Channels', body: 'You post, readers read, and readers cannot see each other. Posts are signed by your device; invite codes can expire, be capped or revoked; a leaver never gets the next key.', category: 'connect', tags: ['ready'], since: '1.4.0', product: 'chat' },
  { icon: Users, title: 'Large groups up to 1,000', body: 'Everyone posts; each post is encrypted once under a shared key that only members’ devices hold, delivered to them over the post-quantum hybrid exchange. Join with invite codes. Text posts only for now.', category: 'connect', tags: ['ready'], since: '1.5.0', product: 'chat' },
  { icon: Fingerprint, title: 'Mobile-number sign-in & QR device linking', body: 'Sign up with a phone number and one-time SMS codes, and link a new device by scanning a QR code. The new device gets its own session and must prove it is the device that was scanned.', category: 'connect', tags: ['setup'], since: '1.5.0', product: 'chat' },
  { icon: ShieldCheck, title: 'Block & Restrict, enforced by the server', body: 'A blocked contact’s messages and calls are dropped by the relay without telling them. A restricted contact can still message you but cannot call you or add you to a group.', category: 'protect', tags: ['ready'], since: '1.5.0', product: 'chat' },
  { icon: Bot, title: 'AI assistant', body: 'Catch me up, Suggest replies, Translate — with your own Anthropic or OpenAI key. Off by default, per conversation, and the text it reads leaves end-to-end encryption.', category: 'connect', tags: ['optin'], since: '1.4.0', product: 'chat' },

  { icon: KeyRound, title: 'Social recovery', body: 'Choose verified contacts as helpers and how many are needed (at least 2, e.g. 3 of 5). They plus a PIN only you know rebuild your recovery key; helpers confirm four words with you first. Not even the server sees it.', category: 'recover', tags: ['setup'], since: '1.4.0', product: 'chat' },
  { icon: History, title: 'Encrypted history backup', body: 'Saves the keys to your history — not the messages — as a .qgbackup only your recovery key opens. Restore it on a new device and relay history becomes readable again.', category: 'recover', tags: ['setup'], since: '1.4.0', product: 'chat' },
  { icon: Fingerprint, title: 'Duress PIN, panic wipe, biometrics', body: 'Erase this device on demand, hide the app in Recent apps, unlock with a strong biometric, or enter a duress PIN that silently wipes the keys.', category: 'protect', tags: ['ready', 'android'], since: '1.4.0', product: 'chat' },

  { icon: WifiOff, title: 'Messages wait instead of failing', body: 'If the relay cannot be reached, a sealed message waits in an encrypted outbox and goes out by itself — expired disappearing messages are never sent.', category: 'resilience', tags: ['ready'], since: '1.4.0', product: 'chat' },
  { icon: Radio, title: 'Nearby delivery', body: 'While the relay is down, waiting messages can hop to QGuard phones in Bluetooth/Wi-Fi range through Google Play services. Still end-to-end encrypted.', category: 'resilience', tags: ['optin', 'android'], since: '1.4.0', product: 'chat' },
  { icon: WifiOff, title: 'Honest outage banner', body: 'Offline, service failing, or unreachable though your internet works — decided from real checks, never a guess, and it says when it cannot tell.', category: 'resilience', tags: ['ready'], since: '1.4.0', product: 'chat' },

  { icon: Building2, title: 'Messenger devices in QGuard Helix', body: 'With the same login, Helix’s Collector console imports the algorithms each of your messenger devices publishes. Older pre-FIPS Kyber devices read as not quantum-safe.', category: 'enterprise', tags: ['setup'], since: '1.4.0', product: 'chat' },
  { icon: Users, title: 'Server-side roles', body: 'Who sees internal panels is a database role, not an email compiled into the app. Panels only ever show the caller’s own data.', category: 'enterprise', tags: ['ready'], since: '1.4.0', product: 'chat' },
  { icon: ShieldCheck, title: 'No message escrow', body: 'No archive device exists, by decision — message content is never retained for organisations.', category: 'enterprise', tags: ['ready'], since: '1.4.0', product: 'chat' },
  { icon: Search, title: 'Hardened contact search', body: 'The directory no longer reveals other people’s emails; searches need three characters and are limited to 60 per five minutes, so it cannot be listed.', category: 'enterprise', tags: ['ready'], since: '1.4.0', product: 'chat' },

  { icon: Lock, title: 'Post-quantum encryption', body: 'Files are sealed with AES-256-GCM under a unique key, wrapped under your PIN-bound vault key and signed with ML-DSA-87 (FIPS 204 Level 5). Shared files and enterprise recovery add NIST ML-KEM-1024.', category: 'protect', tags: ['ready'], since: '', product: 'vault' },
  { icon: FolderLock, title: 'Strictly on-device', body: 'Everything is encrypted and decrypted locally. Your files never touch QGuard’s servers — there is nothing to upload, intercept or leak.', category: 'protect', tags: ['ready'], since: '', product: 'vault' },
  { icon: ShieldCheck, title: 'Tamper-evident, to the last byte', body: 'Every chunk is authenticated and bound to its position, so any change, reorder or truncation is detected and refused before a byte is written.', category: 'protect', tags: ['ready'], since: '', product: 'vault' },
  { icon: LifeBuoy, title: 'Quantum-safe recovery', body: 'Lose your device? An offline recovery key restores your .qvault files on a brand-new machine — no access to the old one required.', category: 'recover', tags: ['setup'], since: '', product: 'vault' },
  { icon: Building2, title: 'Enterprise dual-control', body: 'Hybrid recovery requires both a personal key and an enterprise key — two-person integrity for regulated teams.', category: 'recover', tags: ['setup'], since: '', product: 'vault' },
  { icon: FolderLock, title: 'Files & folders, any size', body: 'Whole folders become one sealed archive with the structure hidden inside the ciphertext. Streamed in 1 MiB chunks, so the app sets no size limit. Folders are desktop-only; Android seals individual files.', category: 'vault', tags: ['ready', 'desktop'], since: '', product: 'vault' },
  { icon: Layers, title: 'Live Crypto Terminal', body: 'Watch the real pipeline as it runs — key sealing, signing and per-chunk progress with true throughput and ETA.', category: 'vault', tags: ['ready'], since: '', product: 'vault' },
  { icon: KeyRound, title: 'PIN-bound vault containers', body: '.qvault v5 wraps each file key under the PIN-bound vault key, so the lock is enforced by the cryptography — not just the interface.', category: 'vault', tags: ['ready'], since: '1.3.11', product: 'vault' },
  { icon: FolderLock, title: 'Portable Hybrid Identity', body: 'A .qgkey lets a vault object be sealed to a person instead of a device, so you can share quantum-encrypted files with someone who must never hold your keys.', category: 'vault', tags: ['ready'], since: '', product: 'vault' },
  { icon: LifeBuoy, title: 'Locks that fail safe', body: 'A workspace lock record that no longer opens goes to a re-authenticated reset — it is never treated as “no lock set”, which would let anyone set their own.', category: 'vault', tags: ['ready'], since: '1.4.2', product: 'both' },
];

export function FeatureAtlas({ product }: { product?: 'chat' | 'vault' }) {
  const items = ATLAS.filter((a) => !product || a.product === product || a.product === 'both');
  const cats = ['all', ...Array.from(new Set(items.map((i) => i.category)))] as Array<Category | 'all'>;
  const [cat, setCat] = useState<Category | 'all'>('all');
  const shown = items.filter((i) => cat === 'all' || i.category === cat);

  return (
    <div>
      <div role="tablist" aria-label="Filter features" className="mt-8 flex flex-wrap justify-center gap-2">
        {cats.map((c) => (
          <button
            key={c}
            role="tab"
            type="button"
            aria-selected={cat === c}
            onClick={() => setCat(c)}
            className={cn(
              'rounded-full border px-4 py-1.5 font-mono text-[11px] font-bold uppercase tracking-wider transition-all duration-200',
              cat === c ? 'border-slate-900 bg-slate-900 text-slate-50 shadow-lg' : 'border-slate-300 bg-white text-slate-600 hover:border-cyan-500 hover:text-cyan-700',
            )}
          >
            {CATEGORY_LABEL[c]}
            <span className={cn('ml-2', cat === c ? 'text-cyan-300' : 'text-slate-400')}>{c === 'all' ? items.length : items.filter((i) => i.category === c).length}</span>
          </button>
        ))}
      </div>
      <motion.div layout className="mt-8 grid gap-5 sm:grid-cols-2 lg:grid-cols-3">
        <AnimatePresence mode="popLayout" initial={false}>
          {shown.map((f) => (
            <motion.div key={f.title} layout initial={{ opacity: 0, scale: 0.94 }} animate={{ opacity: 1, scale: 1 }} exit={{ opacity: 0, scale: 0.94 }} transition={{ duration: 0.3 }}>
              <AtlasCard item={f} />
            </motion.div>
          ))}
        </AnimatePresence>
      </motion.div>
    </div>
  );
}

export function AtlasCard({ item }: { item: AtlasItem }) {
  const { icon: Icon, title, body, tags, since } = item;
  return (
    <TiltCard className="h-full">
      <GlassCard className="qm-shine group h-full p-6" hover={false}>
        <div className="flex items-start justify-between gap-3">
          <span className="flex h-11 w-11 items-center justify-center rounded-xl border border-cyan-200 bg-gradient-to-br from-cyan-50 to-violet-50 text-cyan-700 shadow-[0_8px_24px_rgba(34,211,238,0.18)] transition-transform duration-300 group-hover:scale-110 group-hover:rotate-3">
            <Icon className="h-5 w-5" />
          </span>
          {since && <span className="font-mono text-[10px] font-bold uppercase tracking-widest text-slate-400">v{since}</span>}
        </div>
        <h3 className="mt-4 text-base font-bold text-slate-900">{title}</h3>
        <p className="mt-2 text-sm leading-relaxed text-slate-600">{body}</p>
        <div className="mt-4 flex flex-wrap gap-1.5">
          {tags.map((t) => <Tag key={t} kind={t} />)}
        </div>
      </GlassCard>
    </TiltCard>
  );
}

/* --------------------------------------------------------- numbers ---------- */

const NUMBERS: Array<{ n: number; suffix?: string; label: string; sub: string }> = [
  { n: 32, label: 'people in a group', sub: 'sealed per member device' },
  { n: 1000, label: 'people in a large group', sub: 'one shared key per epoch' },
  { n: 3, label: 'people on a group video call', sub: 'one encrypted link per pair' },
  { n: 3, label: 'group admins', sub: 'plus the owner' },
  { n: 4, label: 'words in a call phrase', sub: '40 bits · 30 s window' },
  { n: 50, label: 'messages between ML-KEM steps', sub: 'ratchet, at most — or 24 h' },
];

export function NumbersStrip() {
  return (
    <div>
      <div className="grid gap-4 sm:grid-cols-3 lg:grid-cols-6">
        {NUMBERS.map((x, i) => (
          <Rise key={x.label} index={i}>
            <GlassCard className="qm-shine h-full p-5 text-center" hover={false}>
              <div className="bg-gradient-to-r from-cyan-500 to-violet-600 bg-clip-text text-5xl font-black tracking-tight text-transparent">
                <CountUp to={x.n} suffix={x.suffix} />
              </div>
              <div className="mt-2 text-sm font-bold text-slate-900">{x.label}</div>
              <div className="mt-1 font-mono text-[10.5px] uppercase tracking-wider text-slate-500">{x.sub}</div>
            </GlassCard>
          </Rise>
        ))}
      </div>
      <p className="mt-4 text-center text-xs text-slate-500">Design limits taken from the implementation — not usage statistics.</p>
    </div>
  );
}

/* ---------------------------------------------------------- release rail ---- */

const RELEASES: Array<{ v: string; date: string; title: string; points: string[] }> = [
  { v: '1.3.8', date: '16 Sep 2026', title: 'Messages are really authenticated', points: ['Sender identity anchored to the device’s published keys', 'Call signals bound to the call’s device', 'Fail-closed end-to-end call media'] },
  { v: '1.3.11', date: '13 Oct 2026', title: 'Device pins, forward secrecy, call v2', points: ['Relay can no longer add a device to your account', 'Prekey rotation + encrypted message-key ledger', 'PIN-bound .qvault v5'] },
  { v: '1.4.0', date: '20 Oct 2026', title: 'Protection you can see and prove', points: ['Protection badge · verify contacts · call phrase', 'Groups · channels · group calls · screen share', 'Recovery · duress PIN · AI assistant · offline delivery'] },
  { v: '1.4.3', date: '20 Oct 2026', title: 'Built for phones', points: ['Signal/Telegram-style list and sheets at phone width', 'Lock resets that explain themselves', 'Prekey and forward-secrecy status fixes'] },
  { v: '1.5.0', date: '22 Oct 2026', title: 'Bigger groups, easier sign-in', points: ['Large groups and channels up to 1,000', 'Mobile-number sign-in · QR device linking', 'Server-enforced Block & Restrict · sealed audit details'] },
];

function versionLt(a: string, b: string) {
  const pa = a.split('.').map(Number);
  const pb = b.split('.').map(Number);
  for (let i = 0; i < 3; i++) {
    if ((pa[i] || 0) !== (pb[i] || 0)) return (pa[i] || 0) < (pb[i] || 0);
  }
  return false;
}

export function ReleaseRail() {
  const calm = useCalm();
  const behind = versionLt(MESSAGING_INSTALLER.version, '1.4.0');
  return (
    <div>
      <div className="relative mt-12">
        <div aria-hidden className="absolute left-0 right-0 top-[19px] hidden h-px bg-gradient-to-r from-transparent via-slate-300 to-transparent lg:block" />
        <motion.div
          aria-hidden
          className="absolute left-0 top-[18px] hidden h-[3px] bg-gradient-to-r from-cyan-400 via-amber-400 to-violet-500 lg:block"
          initial={{ width: calm ? '100%' : 0 }}
          whileInView={{ width: '100%' }}
          viewport={{ once: true, margin: '-100px' }}
          transition={{ duration: 1.6, ease: [0.22, 1, 0.36, 1] }}
        />
        <div className="relative grid gap-5 lg:grid-cols-5">
          {RELEASES.map((r, i) => (
            <Rise key={r.v} index={i}>
              <div>
                <div className="flex items-center gap-3 lg:flex-col lg:items-start">
                  <span className="relative z-10 flex h-10 w-10 items-center justify-center rounded-full border-2 border-slate-900 bg-white font-mono text-[10px] font-black text-slate-900 shadow-[0_6px_20px_rgba(2,6,23,0.2)]">
                    {i + 1}
                  </span>
                  <div>
                    <div className="font-mono text-xs font-black text-cyan-700">v{r.v}</div>
                    <div className="font-mono text-[10px] uppercase tracking-wider text-slate-400">{r.date}</div>
                  </div>
                </div>
                <GlassCard className="mt-3 p-5" hover={false}>
                  <h3 className="text-sm font-bold text-slate-900">{r.title}</h3>
                  <ul className="mt-3 space-y-1.5">
                    {r.points.map((p) => (
                      <li key={p} className="flex items-start gap-2 text-[13px] leading-snug text-slate-600">
                        <Check className="mt-0.5 h-3.5 w-3.5 shrink-0 text-cyan-600" /> {p}
                      </li>
                    ))}
                  </ul>
                </GlassCard>
              </div>
            </Rise>
          ))}
        </div>
      </div>
      {behind && (
        <p className="mx-auto mt-6 max-w-2xl rounded-xl border border-amber-200 bg-amber-50 px-4 py-3 text-center text-xs leading-relaxed text-amber-900" role="note">
          The installer currently served here is <strong>v{MESSAGING_INSTALLER.version}</strong>. Features marked 1.3.11 and 1.4 reach it when that version is published — the download button always shows the version it will give you.
        </p>
      )}
    </div>
  );
}

/* ------------------------------------------------------- platform matrix ---- */

type Cell = 'yes' | 'no' | 'planned';
const PLATFORM_ROWS: Array<{ label: string; windows: Cell; android: Cell; note?: string }> = [
  { label: 'Secure Chat, files and voice notes', windows: 'yes', android: 'yes' },
  { label: '1:1 and group calls (up to 3)', windows: 'yes', android: 'yes' },
  { label: 'Screen sharing in calls', windows: 'yes', android: 'no', note: 'Android needs MediaProjection' },
  { label: 'Quantum Vault — files', windows: 'yes', android: 'yes' },
  { label: 'Quantum Vault — whole folders', windows: 'yes', android: 'no', note: 'Android cannot walk a folder tree' },
  { label: 'Biometric unlock, duress PIN, Recents masking', windows: 'no', android: 'yes' },
  { label: 'Nearby delivery', windows: 'no', android: 'yes', note: 'Google Play services' },
];

function PlatformCell({ v }: { v: Cell }) {
  if (v === 'yes') return <span className="inline-flex items-center gap-1.5 font-semibold text-emerald-700"><Check className="h-4 w-4" aria-hidden />Yes</span>;
  if (v === 'planned') return <span className="inline-flex items-center gap-1.5 font-semibold text-slate-500"><Minus className="h-4 w-4" aria-hidden />Planned</span>;
  return <span className="inline-flex items-center gap-1.5 text-slate-400"><Minus className="h-4 w-4" aria-hidden />Not yet</span>;
}

export function PlatformMatrix() {
  return (
    <GlassCard className="overflow-hidden" hover={false}>
      <div className="overflow-x-auto">
        <table className="w-full min-w-[520px] text-left text-sm">
          <thead>
            <tr className="border-b border-slate-200 bg-slate-50/80 font-mono text-[10.5px] uppercase tracking-widest text-slate-500">
              <th className="px-5 py-3 font-bold">Capability</th>
              <th className="px-5 py-3 font-bold">Windows</th>
              <th className="px-5 py-3 font-bold">Android</th>
            </tr>
          </thead>
          <tbody className="divide-y divide-slate-200">
            {PLATFORM_ROWS.map((r) => (
              <tr key={r.label}>
                <td className="px-5 py-3 text-slate-800">
                  <div className="font-semibold">{r.label}</div>
                  {r.note && <div className="text-xs text-slate-500">{r.note}</div>}
                </td>
                <td className="px-5 py-3"><PlatformCell v={r.windows} /></td>
                <td className="px-5 py-3"><PlatformCell v={r.android} /></td>
              </tr>
            ))}
          </tbody>
        </table>
      </div>
    </GlassCard>
  );
}

/* ---------------------------------------------------------- straight talk --- */

export type Limit = { title: string; body: string };

export const LIMITS: Limit[] = [
  { title: 'Not independently audited', body: 'The implementation is production-oriented, but no outside party has audited it. The per-message ratchet in particular is our own implementation of the published Double Ratchet + sparse ML-KEM shape and is not formally verified — do not rely on it for regulated deployments until an independent review is done.' },
  { title: 'Default forward secrecy follows prekey rotation', body: 'Out of the box each message is sealed with its own hybrid encapsulation to a signed prekey that rotates about daily. Someone who obtains a prekey secret during its epoch could open not-yet-recorded messages sealed to it. The ratchet (opt-in) closes that gap.' },
  { title: 'The relay still sees routing metadata', body: 'It cannot read content, but it knows recipient IDs and queue timing. Sealed sender is designed, not built — the badge and these pages never claim it.' },
  { title: 'Groups are pairwise, not MLS', body: 'In a group each message is sealed separately to every member device, so groups top out at 32 people. MLS was not used because its post-quantum ciphersuites are not yet standardized.' },
  { title: 'Large groups trade per-message keys for one key per epoch', body: 'Posts in a large group (up to 1,000) are encrypted once under a shared key. Only the owner and admins hand out keys and start a new epoch, so after someone leaves, members keep using the key that person held until an owner or admin next opens the group. Large groups carry text posts only.' },
  { title: 'The AI assistant leaves end-to-end encryption', body: 'What you ask it to read goes to Anthropic or OpenAI under your key and their terms. Others in the chat are not told. Answers can be wrong.' },
  { title: 'A call phrase proves a device, not a person', body: 'If a verified contact’s unlocked device is in someone else’s hands the phrase will still match, and it says nothing about whether a voice is synthetic.' },
  { title: 'A compromised endpoint sees plaintext', body: 'Encryption protects data in transit and at rest. Malware on an unlocked device, or secure deletion on SSDs, are outside what any messenger can guarantee.' },
];

export function StraightTalk({ items = LIMITS }: { items?: Limit[] }) {
  const [open, setOpen] = useState<number | null>(0);
  return (
    <GlassCard className="overflow-hidden" hover={false}>
      <ul className="divide-y divide-slate-200">
        {items.map((l, i) => {
          const isOpen = open === i;
          return (
            <li key={l.title}>
              <button
                type="button"
                aria-expanded={isOpen}
                onClick={() => setOpen(isOpen ? null : i)}
                className="flex w-full items-center gap-3 px-5 py-4 text-left transition-colors hover:bg-slate-50"
              >
                <span className="font-mono text-xs font-black text-amber-600">{String(i + 1).padStart(2, '0')}</span>
                <span className="flex-1 text-sm font-bold text-slate-900">{l.title}</span>
                <ChevronDown className={cn('h-4 w-4 text-slate-400 transition-transform duration-200', isOpen && 'rotate-180')} />
              </button>
              <AnimatePresence initial={false}>
                {isOpen && (
                  <motion.div initial={{ height: 0, opacity: 0 }} animate={{ height: 'auto', opacity: 1 }} exit={{ height: 0, opacity: 0 }} transition={{ duration: 0.22 }} className="overflow-hidden">
                    <p className="px-5 pb-5 pl-[3.25rem] text-sm leading-relaxed text-slate-600">{l.body}</p>
                  </motion.div>
                )}
              </AnimatePresence>
            </li>
          );
        })}
      </ul>
    </GlassCard>
  );
}

/* ----------------------------------------------------------- roadmap -------- */

const NEXT: Array<{ title: string; state: string }> = [
  { title: 'Independent protocol review', state: 'Needs an external reviewer' },
  { title: 'Sealed sender', state: 'Designed — awaiting decisions' },
  { title: 'Key transparency', state: 'Designed — awaiting decisions' },
  { title: 'Passkey-protected recovery', state: 'Assessed — needs a decision' },
  { title: 'Enterprise SSO', state: 'Prepared, not implemented' },
  { title: 'iOS', state: 'Feasibility studied' },
];

export function NextUp() {
  return (
    <div className="grid gap-3 sm:grid-cols-2 lg:grid-cols-3">
      {NEXT.map((n, i) => (
        <Rise key={n.title} index={i}>
          <div className="flex items-center justify-between gap-3 rounded-xl border border-dashed border-slate-300 bg-white/70 px-4 py-3">
            <span className="text-sm font-semibold text-slate-800">{n.title}</span>
            <Tag kind="planned">{n.state}</Tag>
          </div>
        </Rise>
      ))}
    </div>
  );
}

/** Section wrapper used by the pages: heading + body, consistent rhythm. */
export function Block({ kicker, title, subtitle, children, narrow }: { kicker?: string; title: React.ReactNode; subtitle?: React.ReactNode; children: React.ReactNode; narrow?: boolean }) {
  return (
    <section className={cn('relative mx-auto px-6 py-14', narrow ? 'max-w-5xl' : 'max-w-[88rem]')}>
      <SectionHeading kicker={kicker} title={title} subtitle={subtitle} />
      <div className="mt-10">{children}</div>
    </section>
  );
}
