/**
 * QGuard Secure Chat — marketing page (/qguard-messaging/secure-chat)
 * Content sourced from qguard-messaging/CHANGELOG.md, docs/security-limitations.md
 * and the feature roadmap. Opt-in / platform-limited / unreviewed features are
 * labelled on the page; nothing is promised that the app does not do.
 */
import { Check, Crown, MessageSquareLock, ShieldCheck, UserCog, Users } from 'lucide-react';
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
import { Aurora, Rise, StageFrame, Tag } from '../_motion';
import { HeroChatScene } from '../_scenes-hero';
import {
  AiBoundary,
  CallPhraseDemo,
  ChannelEpochScene,
  LockStack,
  MeshCallScene,
  ProtectionBadgeExplorer,
  RatchetLab,
  ResilienceFlow,
  ShamirRecovery,
} from '../_scenes-chat';
import { Block, FeatureAtlas, LIMITS, StraightTalk } from '../_catalog';

const TRUST = ['NIST FIPS 203', 'FIPS 204', 'End-to-End Encrypted', 'Zero-Knowledge', 'Hybrid Post-Quantum'];

const STEPS = [
  { title: 'Encrypted on your device', body: 'Text, files, and call frames are sealed with AES-256-GCM before they ever leave you.' },
  { title: 'Quantum-safe key exchange', body: 'Keys are agreed using hybrid X25519 + ML-KEM-1024 (NIST FIPS 203), bound to the transcript and fresh for every message and call.' },
  { title: 'Only your contact can open it', body: 'The relay stores ciphertext and the routing metadata it needs — never content. Verify the safety number to confirm no one is in the middle.' },
];

const VERIFY_STEPS = [
  { title: 'Compare the safety number', body: 'Each of the contact’s devices has a number computed from both devices’ keys. Read it out or compare it in person.' },
  { title: 'Mark it verified', body: 'The core re-derives the number you confirmed and stores the verification bound to the pinned keys. A key change destroys it.' },
  { title: 'Your apps pair themselves', body: 'Each side seals a half-secret to the other’s verified keys over the encrypted chat — hybrid, dual-signed, replay-refused.' },
  { title: 'Ask for the phrase on a call', body: 'Four words from that secret and the call id. Matching words mean the device you verified is on the line.' },
];

const COMPARISON = [
  ['Encryption', 'End-to-end, hybrid post-quantum'],
  ['Algorithms', 'NIST FIPS 203 ML-KEM-1024 + FIPS 204 ML-DSA-65, both signatures must verify'],
  ['Calls', '1:1 and up to 3 people · per-frame E2EE · fresh post-quantum key per link'],
  ['Server access to content', 'None (zero-knowledge)'],
  ['Forward secrecy', 'Prekey rotation by default · per-message ratchet opt-in'],
  ['Disappearing / view-once / time-locked', 'Yes'],
  ['Device verification', 'Device pins, QR approval, safety numbers, call phrase, key-change alerts'],
  ['Recovery', 'Social recovery (k-of-n + PIN) and encrypted history backup'],
  ['Harvest-now-decrypt-later resistant', 'Designed to resist — hybrid ML-KEM-1024 protects every message key'],
];

const ROLES = [
  { icon: Crown, title: 'Owner', body: 'Adds and removes members, appoints up to 3 admins, renames the group and can hand ownership to someone else. A name counts only if the owner at that time sent it.' },
  { icon: UserCog, title: 'Admins (up to 3)', body: 'Add and remove members. Roles are set by the database from the group itself — a member cannot label their own second device an admin.' },
  { icon: Users, title: 'Members', body: 'Up to 32 people. No shared group key: every message is sealed to each member’s devices, so removing someone needs no re-keying. Large groups (up to 1,000) use one shared key per epoch instead.' },
];

export default function SecureChatPage() {
  return (
    <MessagingLayout>
      {/* Hero */}
      <section className="relative px-6 pb-16 pt-28 sm:pt-32">
        <Aurora />
        <div className="mx-auto grid max-w-[88rem] items-center gap-12 grid-cols-[minmax(0,1fr)] lg:grid-cols-2">
          <Reveal>
            <Kicker>Secure Chat</Kicker>
            <h1 className="mt-5 text-4xl font-black leading-[1.05] tracking-tight text-slate-900 sm:text-6xl">
              Conversations built for the <Highlight>quantum era</Highlight>.
            </h1>
            <p className="mt-5 max-w-xl text-base leading-relaxed text-slate-600 sm:text-lg">
              Messages, groups, channels, calls and files — protected by NIST post-quantum cryptography, with protection you can inspect and contacts you can verify. Not even QGuard can read them.
            </p>
            <div className="mt-8 flex flex-wrap items-center gap-3">
              <DownloadButton />
              <GoldButton href="/login">Start a secure chat</GoldButton>
              <GhostButton to="/qguard-messaging/quantum-vault">See Quantum Vault</GhostButton>
            </div>
            <div className="mt-8">
              <TrustStrip items={TRUST} />
            </div>
          </Reveal>

          <Reveal delay={0.15}>
            <StageFrame
              title="Secure Chat // sealed"
              bodyClassName="!px-2 !py-2"
              note={
                <>
                  <span className="inline-flex items-center gap-2"><span className="qm-live-dot" aria-hidden />Messages decrypt on this device only.</span>
                  <span>Example conversation.</span>
                </>
              }
            >
              <HeroChatScene />
            </StageFrame>
          </Reveal>
        </div>
      </section>

      {/* Atlas */}
      <section className="relative mx-auto max-w-[88rem] px-6 py-16">
        <SectionHeading
          kicker="Security & Advanced Features"
          title={<>Built for <Highlight>privacy</Highlight>, end to end</>}
          subtitle="Every capability is checked against the implementation. Each card says when it arrived and whether it is on by default, opt-in, platform-specific or needs setup."
        />
        <FeatureAtlas product="chat" />
      </section>

      {/* Protection badge */}
      <Block
        kicker="Proof, not a label"
        title={<>A protection badge that <Highlight>shows its work</Highlight></>}
        subtitle="The old always-green “E2EE active” line is gone. The chip now reads what the app can actually measure — and says so when it can't."
      >
        <Reveal><ProtectionBadgeExplorer /></Reveal>
      </Block>

      {/* Keys */}
      <Block
        kicker="Forward secrecy, honestly"
        title={<>One key per message — <Highlight>when you turn it on</Highlight></>}
        subtitle="By default every message has its own hybrid encapsulation and prekeys rotate and retire. The post-quantum ratchet goes further, and we label it as the unreviewed opt-in it is."
      >
        <Reveal><RatchetLab /></Reveal>
      </Block>

      {/* Verify */}
      <section className="relative mx-auto max-w-[88rem] px-6 py-14">
        <Aurora />
        <SectionHeading
          kicker="Know who you're talking to"
          title={<>Verify a contact, then <Highlight>prove it on the call</Highlight></>}
          subtitle="Safety numbers settle who owns a device. The call phrase proves that device is the one on the line, so an impostor calling from another device cannot produce it — even with a cloned voice. It proves the device, not the person holding it."
        />
        <div className="mt-10 grid gap-5 md:grid-cols-2 lg:grid-cols-4">
          {VERIFY_STEPS.map((s, i) => (
            <StepCard key={s.title} index={i} title={s.title} body={s.body} />
          ))}
        </div>
        <div className="mt-8">
          <Reveal><CallPhraseDemo /></Reveal>
        </div>
      </section>

      {/* Groups, calls, channels */}
      <Block
        kicker="Together"
        title={<>Groups, group calls and <Highlight>channels</Highlight></>}
        subtitle="Groups use the same hybrid sealing, dual signatures and device checks as a direct chat, with no shared group key. Channels and large groups use a shared key per epoch, delivered only to members' devices over the same hybrid exchange."
      >
        <div className="grid gap-5 md:grid-cols-3">
          {ROLES.map((r, i) => (
            <Rise key={r.title} index={i} className="h-full">
              <GlassCard className="h-full p-6" hover={false}>
                <span className="flex h-11 w-11 items-center justify-center rounded-xl border border-cyan-200 bg-cyan-50 text-cyan-700">
                  <r.icon className="h-5 w-5" />
                </span>
                <h3 className="mt-4 text-base font-bold text-slate-900">{r.title}</h3>
                <p className="mt-2 text-sm leading-relaxed text-slate-600">{r.body}</p>
              </GlassCard>
            </Rise>
          ))}
        </div>
        <div className="mt-8 space-y-8">
          <Reveal><MeshCallScene /></Reveal>
          <Reveal><ChannelEpochScene /></Reveal>
        </div>
      </Block>

      {/* Device privacy */}
      <Block
        kicker="If someone takes your phone"
        title={<>Layers between a stranger and <Highlight>your keys</Highlight></>}
        subtitle="Lock the app, lock each workspace, hide it from Recent apps, and erase the device — or let a duress PIN do it quietly."
      >
        <Reveal><LockStack /></Reveal>
      </Block>

      {/* Recovery */}
      <Block
        kicker="Never locked out"
        title={<>Recovery that does not depend on <Highlight>trusting us</Highlight></>}
        subtitle="Split your recovery key across people you have verified, and back up the keys to your history — neither the server nor any one helper can read them."
      >
        <Reveal><ShamirRecovery /></Reveal>
        <div className="mt-6 flex flex-wrap items-center justify-center gap-3 text-sm text-slate-600">
          <Tag kind="setup">Settings → Recovery</Tag>
          <span>Encrypted history backup saves the keys to your history, not the messages, as a <span className="font-mono text-slate-800">.qgbackup</span> only your recovery key opens.</span>
        </div>
      </Block>

      {/* Resilience */}
      <Block
        kicker="Still delivers"
        title={<>When the relay is down, <Highlight>messages wait — safely</Highlight></>}
        subtitle="A sealed message is kept on your device and goes out by itself. On Android it can even hop to a nearby QGuard phone."
      >
        <Reveal><ResilienceFlow /></Reveal>
      </Block>

      {/* AI */}
      <Block
        kicker="Optional AI, with the boundary drawn"
        title={<>An assistant that <Highlight>asks before it reads</Highlight></>}
        subtitle="Catch me up, suggest replies and translate — with your own key, in conversations you allow, only when you press the button."
      >
        <Reveal><AiBoundary /></Reveal>
      </Block>

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

      {/* Straight talk */}
      <Block narrow kicker="Straight talk" title={<>Where the guarantees <Highlight>stop</Highlight></>} subtitle="What a careful reviewer would ask us. The full list lives in the project’s security-limitations document.">
        <Reveal><StraightTalk items={LIMITS} /></Reveal>
      </Block>

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
              <strong className="text-slate-900"> ML-KEM-1024 + X25519</strong> (NIST FIPS 203) through a transcript-bound combiner, identity and messages are
              <strong className="text-slate-900"> dual-signed with ML-DSA-65 + Ed25519</strong> (FIPS 204), and content is sealed with
              <strong className="text-slate-900"> AES-256-GCM</strong> keyed via <strong className="text-slate-900">HKDF-SHA3-256</strong>.
              Every message is authenticated against the sender’s pinned device keys, replay-protected, and decrypted only on your
              device. Prekeys rotate and are destroyed once every message sealed to them is recorded; the opt-in session ratchet adds a key
              per message and a fresh ML-KEM-1024 exchange at least every 50 messages or 24 hours. Voice and video calls add per-frame end-to-end
              encryption, per-call keys, an authenticated caller and a verifiable call phrase. Private keys never leave your device, and the
              relay is zero-knowledge for content — it can never read your messages, files, or calls — though it does see who talks to whom and when.
            </p>
            <p className="mt-4 flex items-start gap-2 rounded-xl border border-amber-200 bg-amber-50 px-4 py-3 text-xs leading-relaxed text-amber-900">
              <ShieldCheck className="mt-0.5 h-4 w-4 shrink-0" />
              <span>The implementation is production-oriented and has not been independently audited. The relay still sees routing metadata such as recipient IDs and queue timing.</span>
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
