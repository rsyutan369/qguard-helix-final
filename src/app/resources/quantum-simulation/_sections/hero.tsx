/**
 * Quantum Simulation Range — command header.
 *
 * The countdown is the one thing on this page that moves without the visitor
 * doing anything, so it had better be true. It counts to PUBLISHED dates —
 * NIST IR 8547's deprecation and disallowment years, and the CNSA 2.0
 * exclusive-use deadlines — not to an invented "Q-Day". Nobody has published a
 * Q-Day, and a page that invents one forfeits the right to be believed about
 * anything else on it.
 */

import React from 'react';
import { motion } from 'framer-motion';
import { ShieldAlert, Radio } from 'lucide-react';
import CybercoreBackground from '@/components/ui/cyberscore-section-hero';
import { TRANSITION_MILESTONES, milestoneClock, type MilestoneSeverity } from '@/lib/quantum-sim';
import { PROVENANCE, QSR, tint } from '../_theme';
import { Cite, ProvenanceBadge } from '../_ui';

const SEVERITY_COLOR: Record<MilestoneSeverity, string> = {
  info: QSR.live,
  deadline: QSR.model,
  'hard-stop': QSR.broken,
};

/** The three milestones worth a live counter. Info-tier dates are in the timeline section. */
const HEADLINE_MILESTONE_IDS = ['ir8547-deprecate', 'cnsa-web-exclusive', 'ir8547-disallow'];

function CountdownCell({ milestoneId, now }: { milestoneId: string; now: number }) {
  const milestone = TRANSITION_MILESTONES.find((m) => m.id === milestoneId);
  if (!milestone) return null;
  const clock = milestoneClock(milestone, now);
  const accent = SEVERITY_COLOR[milestone.severity];

  return (
    <div
      className="min-w-0 flex-1 rounded-xl border px-4 py-3.5 backdrop-blur-sm"
      style={{ borderColor: tint(accent, 0.22), background: 'rgba(4,7,16,0.62)' }}
      title={milestone.detail}
    >
      <div className="flex items-center justify-between gap-2">
        <span className="font-mono text-[9px] font-bold uppercase tracking-[0.2em]" style={{ color: accent }}>
          {milestone.authority}
        </span>
        <Cite source={milestone.citation} />
      </div>
      <div className="mt-2 flex items-baseline gap-1.5 font-mono tabular-nums">
        <span className="text-[26px] font-black leading-none" style={{ color: accent }}>
          {clock.elapsed ? '—' : clock.days.toLocaleString()}
        </span>
        <span className="text-[10px] uppercase tracking-[0.14em]" style={{ color: QSR.inkMuted }}>
          days
        </span>
        <span className="ml-1 text-[11px]" style={{ color: QSR.inkFaint }}>
          {clock.elapsed ? 'elapsed' : `${String(clock.hours).padStart(2, '0')}:${String(clock.minutes).padStart(2, '0')}:${String(clock.seconds).padStart(2, '0')}`}
        </span>
      </div>
      <p className="mt-2 text-[11px] leading-snug" style={{ color: QSR.inkSoft }}>
        {milestone.title}
      </p>
    </div>
  );
}

export interface HeroProps {
  now: number;
  animate: boolean;
  /**
   * Beam density for the backdrop, from the Performance Manager's tier. Each
   * beam is an independently animated compositor layer with a box-shadow, so
   * the count is a real budget rather than a taste decision.
   */
  beamCount: number;
  onEnterRange: () => void;
}

export default function Hero({ now, animate, beamCount, onEnterRange }: HeroProps) {
  return (
    <header className="qs-cybercore-hero relative overflow-hidden border-b" style={{ borderColor: QSR.hairline }}>
      {animate && beamCount > 0 && <CybercoreBackground beamCount={beamCount} />}

      <div className="relative z-10 mx-auto max-w-[1500px] px-4 py-14 sm:px-6 md:py-20">
        <motion.div
          initial={animate ? { opacity: 0, y: 18 } : false}
          animate={{ opacity: 1, y: 0 }}
          transition={{ duration: 0.7, ease: [0.22, 1, 0.36, 1] }}
          className="max-w-4xl"
        >
          <div className="flex flex-wrap items-center gap-2.5">
            <span
              className="inline-flex items-center gap-1.5 rounded-full border px-2.5 py-1 font-mono text-[10px] font-bold uppercase tracking-[0.24em]"
              style={{ color: QSR.live, borderColor: tint(QSR.live, 0.3), background: tint(QSR.live, 0.08) }}
            >
              <Radio className="h-3 w-3" />
              QGuard Helix · Quantum Range
            </span>
            <span className="font-mono text-[10px] uppercase tracking-[0.18em]" style={{ color: QSR.inkMuted }}>
              FIPS 203 / 204 / 205 · NIST IR 8547 · CNSA 2.0
            </span>
          </div>

          <h1 className="mt-5 text-4xl font-black leading-[1.03] tracking-tight text-white sm:text-5xl md:text-[64px]">
            Quantum Attack
            <br />
            <span style={{ color: QSR.live }}>Simulation</span> Range
          </h1>

          <p className="mt-6 max-w-2xl text-[15px] leading-relaxed" style={{ color: QSR.inkSoft }}>
            A working instrument, not an animation. It runs a real state-vector quantum simulator, factors real numbers with
            Shor's algorithm, performs real ML-KEM key encapsulation in your browser, and builds byte-accurate TLS 1.3 records
            so you can see exactly which bytes an adversary is recording today.
          </p>

          <div className="mt-6 flex flex-wrap items-center gap-3">
            <button
              type="button"
              onClick={onEnterRange}
              className="inline-flex items-center gap-2 rounded-lg px-5 py-3 font-mono text-[11px] font-bold uppercase tracking-[0.16em] transition-transform hover:scale-[1.02]"
              style={{ background: QSR.live, color: '#04060e', boxShadow: `0 0 32px ${tint(QSR.live, 0.35)}` }}
            >
              Enter the range
            </button>
            <span className="inline-flex items-center gap-2 text-[11px]" style={{ color: QSR.inkMuted }}>
              <ShieldAlert className="h-3.5 w-3.5" style={{ color: QSR.model }} />
              Simulation only. No live systems are contacted.
            </span>
          </div>
        </motion.div>

        {/* ── Live countdown to published deadlines ─────────────────────── */}
        <motion.div
          initial={animate ? { opacity: 0, y: 20 } : false}
          animate={{ opacity: 1, y: 0 }}
          transition={{ duration: 0.7, delay: 0.15, ease: [0.22, 1, 0.36, 1] }}
          className="mt-10"
        >
          <div className="mb-2.5 flex items-center gap-2">
            <span className="font-mono text-[10px] font-bold uppercase tracking-[0.24em]" style={{ color: QSR.inkMuted }}>
              Time remaining on the published transition deadlines
            </span>
            <ProvenanceBadge kind="published" compact />
          </div>
          <div className="flex flex-col gap-3 sm:flex-row">
            {HEADLINE_MILESTONE_IDS.map((id) => (
              <CountdownCell key={id} milestoneId={id} now={now} />
            ))}
          </div>
        </motion.div>

        {/* ── Provenance contract ───────────────────────────────────────── */}
        <motion.div
          initial={animate ? { opacity: 0 } : false}
          animate={{ opacity: 1 }}
          transition={{ duration: 0.8, delay: 0.3 }}
          className="mt-8 rounded-xl border px-4 py-3.5 backdrop-blur-sm"
          style={{ borderColor: QSR.hairline, background: 'rgba(4,7,16,0.55)' }}
        >
          <div className="mb-2.5 font-mono text-[10px] font-bold uppercase tracking-[0.22em]" style={{ color: QSR.inkMuted }}>
            Every number on this page carries one of these
          </div>
          <div className="grid gap-3 sm:grid-cols-3">
            {(Object.keys(PROVENANCE) as Array<keyof typeof PROVENANCE>).map((key) => (
              <div key={key} className="flex gap-2.5">
                <ProvenanceBadge kind={key} />
                <p className="min-w-0 text-[11px] leading-snug" style={{ color: QSR.inkFaint }}>
                  {PROVENANCE[key].description}
                </p>
              </div>
            ))}
          </div>
        </motion.div>
      </div>
    </header>
  );
}
