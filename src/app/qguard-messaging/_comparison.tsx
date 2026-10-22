/**
 * Messenger comparison for the QGuard Messaging overview page.
 *
 * QGuard cells come from qguard-messaging/docs/cryptographic-design.md and
 * docs/security-limitations.md. Competitor cells come only from public sources
 * listed in SOURCES, as of COMPARED_AS_OF. Where a vendor has published nothing,
 * the cell says so rather than guessing; rows where others lead stay in.
 * Re-check every competitor cell before changing COMPARED_AS_OF.
 */
import React from 'react';
import { motion } from 'motion/react';
import { Check, Minus, ShieldCheck, X } from 'lucide-react';
import { cn } from '@/lib/utils';
import { GlassCard } from './_shared';
import { useCalm } from './_motion';

const COMPARED_AS_OF = 'October 2026';

type Mark = 'yes' | 'partial' | 'no';
type Cell = { v: Mark; note?: string };
type AppKey = 'qguard' | 'signal' | 'whatsapp' | 'telegram';
type Row = { label: string; detail?: string } & Record<AppKey, Cell>;
type Group = { title: string; rows: Row[] };

const APPS: Array<{ key: AppKey; name: string; short: string; stack: string; mono: string; tone: string }> = [
  { key: 'qguard', name: 'QGuard Messaging', short: 'QGuard', stack: 'X25519 + ML-KEM-1024 · Ed25519 + ML-DSA-65', mono: 'Q', tone: '' },
  { key: 'signal', name: 'Signal', short: 'Signal', stack: 'PQXDH + SPQR (ML-KEM)', mono: 'S', tone: 'bg-[#3a76f0]' },
  { key: 'whatsapp', name: 'WhatsApp', short: 'WhatsApp', stack: 'Signal Protocol, classical keys', mono: 'W', tone: 'bg-[#25d366]' },
  { key: 'telegram', name: 'Telegram', short: 'Telegram', stack: 'MTProto 2.0 · cloud chats by default', mono: 'T', tone: 'bg-[#229ed9]' },
];

const y = (note?: string): Cell => ({ v: 'yes', note });
const p = (note?: string): Cell => ({ v: 'partial', note });
const n = (note?: string): Cell => ({ v: 'no', note });

const GROUPS: Group[] = [
  {
    title: 'Post-quantum protection',
    rows: [
      { label: 'Post-quantum key exchange', detail: 'ML-KEM · NIST FIPS 203', qguard: y('ML-KEM-1024 on every message'), signal: y('Rolling out to all chats'), whatsapp: n('No public disclosure'), telegram: n() },
      { label: 'Post-quantum signatures', detail: 'ML-DSA · NIST FIPS 204', qguard: y('Ed25519 + ML-DSA-65, both verified'), signal: n(), whatsapp: n(), telegram: n() },
      { label: 'Post-quantum key exchange for calls', detail: 'Voice, video and screen share', qguard: y('Fresh hybrid key per call'), signal: p('Not publicly documented'), whatsapp: n(), telegram: n() },
      { label: 'Post-quantum file & folder vault', detail: 'Encrypted on the device, never uploaded', qguard: y('AES-256 + ML-DSA-87 .qvault'), signal: n(), whatsapp: n(), telegram: n() },
      { label: 'Post-quantum status shown per chat', detail: 'Built from evidence the device holds', qguard: y('Protection badge'), signal: n(), whatsapp: n(), telegram: n() },
    ],
  },
  {
    title: 'End-to-end encryption',
    rows: [
      { label: 'End-to-end encrypted by default', detail: 'Every one-to-one chat', qguard: y(), signal: y(), whatsapp: y(), telegram: p('Secret Chats only, opt-in') },
      { label: 'End-to-end encrypted group chats', qguard: y('32, or 1,000 in large groups'), signal: y(), whatsapp: y(), telegram: n('Cloud chats') },
      { label: 'End-to-end encrypted 1:1 calls', qguard: y(), signal: y(), whatsapp: y(), telegram: y() },
      { label: 'End-to-end encrypted group calls', qguard: p('Up to 3 people'), signal: y(), whatsapp: y(), telegram: y('Conference calls') },
    ],
  },
  {
    title: 'Verification & trust',
    rows: [
      { label: 'Verify a contact’s keys', detail: 'Safety number or security code', qguard: y(), signal: y(), whatsapp: y(), telegram: p('Secret Chats only') },
      { label: 'Per-call verification code', detail: 'Compared aloud during the call', qguard: y('4 words, verified devices'), signal: n(), whatsapp: n(), telegram: y('4 emoji') },
      { label: 'Enterprise crypto-posture reporting', detail: 'Devices’ algorithms visible to security teams', qguard: y('QGuard Helix'), signal: n(), whatsapp: n(), telegram: n() },
    ],
  },
  {
    title: 'Recovery & resilience',
    rows: [
      { label: 'Social recovery', detail: 'Trusted contacts help restore your key', qguard: y('Your choice of helpers + PIN'), signal: n(), whatsapp: n(), telegram: n() },
      { label: 'Duress PIN & panic wipe', qguard: y('Android'), signal: n(), whatsapp: n(), telegram: n() },
      { label: 'Nearby delivery without the server', detail: 'Bluetooth / Wi-Fi, still end-to-end', qguard: y('Android, opt-in'), signal: n(), whatsapp: n(), telegram: n() },
    ],
  },
  {
    title: 'Where others lead today',
    rows: [
      { label: 'Sealed sender', detail: 'Server does not learn who sent a message', qguard: n('Designed, not built'), signal: y(), whatsapp: n(), telegram: n() },
      { label: 'iOS app', qguard: n('Feasibility studied'), signal: y(), whatsapp: y(), telegram: y() },
      { label: 'Independent cryptographic review', qguard: n('Planned'), signal: y('Formal analyses published'), whatsapp: p('Protocol analysed, app closed'), telegram: p('Academic analyses of MTProto') },
    ],
  },
];

const SOURCES: Array<{ label: string; href: string }> = [
  { label: 'Signal — PQXDH', href: 'https://signal.org/blog/pqxdh/' },
  { label: 'Signal — SPQR / Triple Ratchet', href: 'https://signal.org/blog/spqr/' },
  { label: 'Surfshark — post-quantum status of Big Tech apps (Sep 2026)', href: 'https://surfshark.com/research/chart/post-quantum-big-tech' },
  { label: 'Telegram — Secret Chats FAQ', href: 'https://telegram.org/faq#secret-chats' },
  { label: 'Telegram — encrypted conference calls', href: 'https://telegram.org/blog/group-calls-made-easy' },
];

const MARK_LABEL: Record<Mark, string> = { yes: 'Yes', partial: 'Partial', no: 'No' };

function MarkIcon({ v, featured }: { v: Mark; featured?: boolean }) {
  if (v === 'yes') {
    return (
      <span
        className={cn(
          'flex h-6 w-6 items-center justify-center rounded-full text-[#ffffff]',
          featured ? 'bg-gradient-to-br from-cyan-500 to-violet-600 shadow-[0_6px_18px_rgba(124,58,237,0.35)]' : 'bg-violet-500/90',
        )}
      >
        <Check className="h-3.5 w-3.5" strokeWidth={3} aria-hidden />
      </span>
    );
  }
  if (v === 'partial') {
    return (
      <span className="flex h-6 w-6 items-center justify-center rounded-full bg-amber-400 text-[#ffffff]">
        <Minus className="h-3.5 w-3.5" strokeWidth={3} aria-hidden />
      </span>
    );
  }
  return (
    <span className="flex h-6 w-6 items-center justify-center text-slate-300">
      <X className="h-4 w-4" strokeWidth={2.5} aria-hidden />
    </span>
  );
}

function CompareCell({ cell, featured, index }: { cell: Cell; featured: boolean; index: number }) {
  const calm = useCalm();
  return (
    <td className={cn('px-1 py-3.5 text-center align-middle sm:px-3', featured && 'bg-gradient-to-r from-cyan-50/90 via-violet-50/90 to-cyan-50/90')}>
      <motion.div
        className="flex flex-col items-center gap-1"
        initial={calm ? false : { opacity: 0, scale: 0.6 }}
        whileInView={{ opacity: 1, scale: 1 }}
        viewport={{ once: true, margin: '-40px' }}
        transition={{ duration: 0.35, ease: [0.22, 1, 0.36, 1], delay: Math.min(index, 6) * 0.04 }}
      >
        <MarkIcon v={cell.v} featured={featured} />
        <span className="sr-only">{MARK_LABEL[cell.v]}</span>
        {cell.note && (
          <span className={cn('hidden max-w-[9.5rem] text-[10.5px] leading-tight sm:block', featured ? 'font-semibold text-violet-800' : 'text-slate-500')}>{cell.note}</span>
        )}
      </motion.div>
    </td>
  );
}

function AppHeader({ app }: { app: (typeof APPS)[number] }) {
  const featured = app.key === 'qguard';
  return (
    <th
      scope="col"
      className={cn(
        'px-1 pb-3 pt-4 text-center align-bottom font-normal sm:px-3 sm:pb-4 sm:pt-5',
        featured && 'rounded-t-2xl bg-gradient-to-b from-slate-900 to-slate-800 text-[#ffffff]',
      )}
    >
      <div className="flex flex-col items-center gap-1.5 sm:gap-2">
        {featured ? (
          <span className="flex h-8 w-8 items-center justify-center rounded-xl border border-[#d4af37]/50 bg-slate-950 shadow-[0_10px_30px_rgba(212,175,55,0.35)] sm:h-12 sm:w-12 sm:rounded-2xl">
            <ShieldCheck className="h-4 w-4 text-[#d4af37] sm:h-6 sm:w-6" aria-hidden />
          </span>
        ) : (
          <span className={cn('flex h-8 w-8 items-center justify-center rounded-full text-sm font-black text-[#ffffff] sm:h-12 sm:w-12 sm:text-lg', app.tone)} aria-hidden>
            {app.mono}
          </span>
        )}
        <span className={cn('text-[10px] font-bold sm:text-sm', featured ? 'text-[#ffffff]' : 'text-slate-900')}>
          <span className="sm:hidden">{app.short}</span>
          <span className="hidden sm:inline">{app.name}</span>
        </span>
        <span className={cn('hidden min-h-[2.6em] max-w-[10rem] font-mono text-[9.5px] uppercase leading-snug tracking-wider sm:block', featured ? 'text-cyan-200' : 'text-slate-400')}>{app.stack}</span>
        {featured && (
          <span className="hidden rounded-full border sm:inline-block border-[#d4af37]/50 bg-[#d4af37]/15 px-2.5 py-0.5 font-mono text-[9px] font-bold uppercase tracking-[0.18em] text-[#d4af37]">Quantum-first</span>
        )}
      </div>
    </th>
  );
}

export function MessengerComparison() {
  return (
    <div>
      <GlassCard className="overflow-hidden" hover={false}>
        <div className="overflow-x-auto">
          <table className="w-full border-collapse text-left text-sm sm:min-w-[820px]">
            <caption className="sr-only">QGuard Messaging compared with Signal, WhatsApp and Telegram, as of {COMPARED_AS_OF}</caption>
            <thead>
              <tr className="border-b-2 border-slate-900">
                <th scope="col" className="bg-white px-3 pb-4 align-bottom sm:sticky sm:left-0 sm:z-10 sm:min-w-[15rem] sm:px-5">
                  <span className="hidden rounded-full sm:inline-flex border border-slate-300 px-3 py-1 font-mono text-[10.5px] font-bold uppercase tracking-widest text-slate-500">Capability</span>
                </th>
                {APPS.map((a) => <AppHeader key={a.key} app={a} />)}
              </tr>
            </thead>
            {GROUPS.map((g) => (
              <tbody key={g.title} className="divide-y divide-slate-100">
                <tr className="bg-slate-50/90">
                  <th
                    scope="colgroup"
                    colSpan={APPS.length + 1}
                    className={cn(
                      'px-3 py-2.5 text-left font-mono text-[10.5px] font-black uppercase tracking-[0.2em] sm:px-5',
                      g.title === 'Where others lead today' ? 'text-amber-700' : 'text-cyan-700',
                    )}
                  >
                    {g.title}
                  </th>
                </tr>
                {g.rows.map((r) => (
                  <tr key={r.label} className="transition-colors hover:bg-slate-50/60">
                    <th scope="row" className="bg-white px-3 py-3.5 text-left font-normal sm:sticky sm:left-0 sm:z-10 sm:px-5">
                      <div className="text-[13px] font-semibold text-slate-900 sm:text-sm">{r.label}</div>
                      {r.detail && <div className="mt-0.5 text-[11px] text-slate-500 sm:text-xs">{r.detail}</div>}
                      {r.qguard.note && <div className="mt-1 text-[11px] font-semibold text-violet-700 sm:hidden">QGuard: {r.qguard.note}</div>}
                    </th>
                    {APPS.map((a, i) => (
                      <CompareCell key={a.key} cell={r[a.key]} featured={a.key === 'qguard'} index={i} />
                    ))}
                  </tr>
                ))}
              </tbody>
            ))}
          </table>
        </div>
      </GlassCard>

      <div className="mt-5 flex flex-wrap items-center justify-center gap-x-6 gap-y-2 text-xs text-slate-600">
        <span className="inline-flex items-center gap-2"><MarkIcon v="yes" featured /> Available</span>
        <span className="inline-flex items-center gap-2"><MarkIcon v="partial" /> Partial, limited or not publicly documented</span>
        <span className="inline-flex items-center gap-2"><MarkIcon v="no" /> Not available or no public evidence</span>
      </div>

      <p className="mx-auto mt-4 max-w-3xl text-center text-xs leading-relaxed text-slate-500">
        Compared from each vendor’s public documentation as of {COMPARED_AS_OF}; competitors may have changed since. “No public evidence” is not proof a feature is absent.
        Signal, WhatsApp and Telegram are trademarks of their owners; QGuard is not affiliated with them. Sources:{' '}
        {SOURCES.map((s, i) => (
          <React.Fragment key={s.href}>
            <a href={s.href} target="_blank" rel="noopener noreferrer" className="text-cyan-700 underline-offset-2 hover:underline">{s.label}</a>
            {i < SOURCES.length - 1 ? ' · ' : '.'}
          </React.Fragment>
        ))}
      </p>
    </div>
  );
}
