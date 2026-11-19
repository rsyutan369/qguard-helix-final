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
import { ArrowUpRight, ShieldAlert } from 'lucide-react';
import { ButtonDot, Chars } from '@/pages/landing-chars';
import { TRANSITION_MILESTONES, milestoneClock, type MilestoneSeverity } from '@/lib/quantum-sim';
import { PROVENANCE, QSR, qsrThemeVars } from '../_theme';
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
      className="qsr-deadline"
      style={{ borderColor: QSR.hairline }}
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

const HERO_TITLE = 'Quantum Attack Simulation Range';
const CONSOLE_THEME = qsrThemeVars('dark');

export default function Hero({ now, onEnterRange }: { now: number; onEnterRange: () => void }) {
  return (
    <header className="qsr-hero">
      <div className="lp-wrap">
        <div className="qsr-hero__grid">
          <div className="qsr-hero__copy">
            <p className="lp-eyebrow">Interactive cryptography lab</p>
            <h1 className="qsr-hero__title qsr-heading" data-letters="load" aria-label={HERO_TITLE}>
              <Chars text="Quantum Attack" />{' '}
              <span className="qsr-hero__accent"><Chars text="Simulation Range" /></span>
            </h1>
            <p className="lp-lede">
              Follow a quantum threat from exposure to mitigation. Run a state-vector simulation, inspect TLS 1.3 records,
              and measure post-quantum algorithms in your browser.
            </p>
            <div className="qsr-hero__actions" data-lp-reveal>
              <button type="button" onClick={onEnterRange} className="lp-btn lp-btn--primary lp-btn--dot qsr-primary">
                Enter the range <ButtonDot />
              </button>
              <a href="#transition-timeline" className="qsr-hero__link">
                Transition timeline <ArrowUpRight aria-hidden="true" size={16} />
              </a>
            </div>
            <p className="qsr-hero__note" data-lp-reveal>
              <ShieldAlert aria-hidden="true" size={16} /> Exercises run on local simulation data.
            </p>
          </div>

          <div className="qsr-deadlines lp-dark" style={CONSOLE_THEME} data-lp-reveal>
            <div className="lp-console__bar">
              <h2>Published transition deadlines</h2>
              <ProvenanceBadge kind="published" compact />
            </div>
            {HEADLINE_MILESTONE_IDS.map((id) => <CountdownCell key={id} milestoneId={id} now={now} />)}
            <p className="qsr-deadlines__foot">Milestones apply according to each source’s scope.</p>
          </div>
        </div>

        <div className="qsr-provenance" aria-label="Evidence sources" data-lp-reveal>
          {(Object.keys(PROVENANCE) as Array<keyof typeof PROVENANCE>).map((key) => (
            <div key={key} className="qsr-provenance__item">
              <ProvenanceBadge kind={key} />
              <p>{PROVENANCE[key].description}</p>
            </div>
          ))}
        </div>
      </div>
    </header>
  );
}
