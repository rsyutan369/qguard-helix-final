/**
 * QGuard Secure Chat — marketing page (/qguard-messaging/secure-chat)
 * Content sourced from qguard-messaging/CHANGELOG.md, docs/security-limitations.md
 * and the feature roadmap. Opt-in / platform-limited / unreviewed features are
 * labelled on the page; nothing is promised that the app does not do.
 */
import { Check, Crown, MessageSquareLock, ShieldCheck, UserCog, Users } from 'lucide-react';
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
import { Aurora, Rise, StageFrame, Tag } from '../_motion';
import { HeroChatScene } from '../_scenes-hero';
import { LocalWorkflowLink, LocalWorkflows } from '../_local-workflows';
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

const TRUST = ['End-to-End Encrypted Chat & Calls', 'Hybrid Key Establishment', 'Device Verification'];

const STEPS = [
  { title: 'Encrypted on your device', body: 'The app encrypts message content and attachments with AES-256-GCM. Calls use separate AES-256-GCM media keys per peer link.' },
  { title: 'Hybrid key establishment', body: 'Default direct chat envelopes and call handshakes use X25519 + ML-KEM-1024. Ratcheted sessions and shared group epochs manage keys differently.' },
  { title: 'Verify the receiving device', body: 'The relay stores ciphertext and delivery metadata. Compare the safety number through a trusted channel to check the contact device’s keys.' },
];

const VERIFY_STEPS = [
  { title: 'Compare the safety number', body: 'Each of the contact’s devices has a number computed from both devices’ keys. Read it out or compare it in person.' },
  { title: 'Mark it verified', body: 'The core re-derives the number you confirmed and stores the verification bound to the pinned keys. A key change destroys it.' },
  { title: 'Your apps pair themselves', body: 'Each side seals a half-secret to the other’s verified keys over the encrypted chat — hybrid, dual-signed, replay-refused.' },
  { title: 'Ask for the phrase on a call', body: 'Four words from that secret and the call id. Matching words mean the device you verified is on the line.' },
];

const COMPARISON = [
  ['Encryption', 'End-to-end, hybrid post-quantum'],
  ['Direct message envelopes', 'X25519 + ML-KEM-1024 · Ed25519 + ML-DSA-65 · AES-256-GCM'],
  ['Calls', '1:1 and up to 3 people · per-frame E2EE · fresh post-quantum key per link'],
  ['Relay visibility', 'Ciphertext, recipient IDs, group membership and delivery timing'],
  ['Forward secrecy', 'Prekey rotation by default · per-message ratchet opt-in'],
  ['Disappearing / view-once / time-locked', 'Yes'],
  ['Device verification', 'Device pins, QR approval, safety numbers, call phrase, key-change alerts'],
  ['Recovery', 'Social recovery (k-of-n + PIN) and encrypted history backup'],
  ['Channels and large groups', 'Shared AES-256-GCM epoch keys delivered through hybrid envelopes'],
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
              Send encrypted messages and attachments, make voice and video calls, and verify contact devices. Direct chats, group channels and call media use different key schedules.
            </p>
            <MessagingBuildScope />
            <div className="mt-8 flex flex-wrap items-center gap-3">
              <DownloadButton />
              <GhostButton to="/qguard-messaging/quantum-vault">See Quantum Vault</GhostButton>
              <LocalWorkflowLink>Explore Offgrid Mesh</LocalWorkflowLink>
            </div>
            <div className="mt-8">
              <TrustStrip items={TRUST} />
            </div>
          </Reveal>

          <Reveal delay={0.15}>
            <StageFrame
              title="Secure Chat illustration"
              bodyClassName="!px-2 !py-2"
              note={
                <>
                  <span className="inline-flex items-center gap-2"><span className="qm-live-dot" aria-hidden />Intended recipients’ devices decrypt the messages.</span>
                  <span>Example conversation.</span>
                </>
              }
            >
              <HeroChatScene />
            </StageFrame>
          </Reveal>
        </div>
      </section>

      <LocalWorkflows page="chat" />

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
        subtitle="The badge checks available recipient devices, their published suites and trust status. It shows when there is insufficient evidence for a protection label."
      >
        <Reveal><ProtectionBadgeExplorer /></Reveal>
      </Block>

      {/* Keys */}
      <Block
        kicker="Forward secrecy, honestly"
        title={<>One key per message — <Highlight>when you turn it on</Highlight></>}
        subtitle="Default direct envelopes use fresh hybrid encapsulation to a rotating signed prekey. The optional session ratchet requires support and opt-in on both devices. It has not been independently reviewed."
      >
        <Reveal><RatchetLab /></Reveal>
      </Block>

      {/* Verify */}
      <section className="relative mx-auto max-w-[88rem] px-6 py-14">
        <Aurora />
        <SectionHeading
          kicker="Know who you're talking to"
          title={<>Verify a contact device, then <Highlight>check it on a call</Highlight></>}
          subtitle="Compare a safety number over a trusted channel. On a 1:1 call, compare the four words to check that the paired device is on the line. The phrase does not identify the speaker or detect synthetic media."
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
        subtitle="Small groups use the same hybrid sealing, dual signatures and device checks as a direct chat, with no shared group key. Channels and large groups use a shared key per epoch, delivered only to members' devices over the same hybrid exchange."
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
        subtitle="Use workspace locks. Android also offers biometric app unlock, Recent apps masking and local app-data wipe controls."
      >
        <Reveal><LockStack /></Reveal>
      </Block>

      {/* Recovery */}
      <Block
        kicker="Optional recovery"
        title={<>Recovery that does not depend on <Highlight>trusting us</Highlight></>}
        subtitle="Set up recovery before losing a device. Verified helpers can provide shares that combine with your recovery PIN or passphrase. Back up history keys separately."
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
        subtitle="The encrypted outbox queues eligible messages for retry. Android also has opt-in Nearby delivery through Google Play services, separate from Offgrid Mesh."
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

      <Block kicker="Security by workflow" title={<>What protects <Highlight>chat, media and local delivery</Highlight></>}>
        <Reveal><SecurityCoverage area="chat" /></Reveal>
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
              On supported devices, calls use AES-256-GCM on encoded audio and video frames in addition to WebRTC transport protection. Call setup fails if the required media encryption cannot be installed. Screen sharing uses the same video encryption on supported desktop video calls. The encrypted history ledger retains keys for already-opened messages, including while the opt-in ratchet is active.
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
        body="Install QGuard Messaging, then compare safety numbers in the app before sharing sensitive information."
        secondary={{ label: 'Back to Overview', to: '/qguard-messaging' }}
      />
    </MessagingLayout>
  );
}
