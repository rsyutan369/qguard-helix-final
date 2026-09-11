/**
 * Quantum Simulation Range — the live telemetry feed.
 *
 * The terminal aesthetic of the page this replaces, kept. Its content, not.
 *
 * Every line here is an event that happened in this session, printed with the
 * number the event actually produced. There is no timer emitting plausible
 * chatter — if nothing is happening, the feed is quiet, and the "awaiting" row
 * says so rather than inventing traffic to fill the space.
 */

import React from 'react';
import { AnimatePresence, motion } from 'framer-motion';
import { Terminal, Trash2 } from 'lucide-react';
import type { RunLogEntry, RunLogLevel } from '../_state';
import { QSR, tint } from '../_theme';

const LEVEL_COLOR: Record<RunLogLevel, string> = {
  info: QSR.inkSoft,
  measure: QSR.live,
  alert: QSR.broken,
  good: QSR.safe,
};

const LEVEL_TAG: Record<RunLogLevel, string> = {
  info: 'INFO',
  measure: 'MEAS',
  alert: 'ALRT',
  good: ' OK ',
};

function timestamp(date: Date): string {
  return `${String(date.getHours()).padStart(2, '0')}:${String(date.getMinutes()).padStart(2, '0')}:${String(date.getSeconds()).padStart(2, '0')}`;
}

export default function RunLog({ entries, onClear }: { entries: RunLogEntry[]; onClear: () => void }) {
  return (
    <div className="flex h-full flex-col overflow-hidden rounded-xl border" style={{ borderColor: QSR.hairline, background: '#03050d' }}>
      <div className="flex shrink-0 items-center justify-between gap-2 border-b px-3 py-2" style={{ borderColor: QSR.hairline }}>
        <span className="flex items-center gap-1.5">
          <Terminal className="h-3.5 w-3.5" style={{ color: QSR.live }} />
          <span className="font-mono text-[9.5px] font-bold uppercase tracking-[0.18em]" style={{ color: QSR.live }}>
            Session telemetry
          </span>
        </span>
        <span className="flex items-center gap-2">
          <span className="flex items-center gap-1 font-mono text-[9px] uppercase tracking-[0.12em]" style={{ color: QSR.inkFaint }}>
            <span className="relative flex h-1.5 w-1.5">
              <span className="absolute inline-flex h-full w-full animate-ping rounded-full opacity-70" style={{ background: QSR.safe }} />
              <span className="relative inline-flex h-1.5 w-1.5 rounded-full" style={{ background: QSR.safe }} />
            </span>
            {entries.length} events
          </span>
          <button
            type="button"
            onClick={onClear}
            aria-label="Clear feed"
            className="rounded p-1 transition-colors hover:text-slate-200"
            style={{ color: QSR.inkFaint }}
          >
            <Trash2 className="h-3 w-3" />
          </button>
        </span>
      </div>

      <div className="qsr-scroll min-h-0 flex-1 overflow-y-auto px-3 py-2 font-mono text-[10.5px] leading-[1.6]">
        {entries.length === 0 ? (
          <div className="py-6 text-center" style={{ color: QSR.inkFaint }}>
            <div>Feed idle.</div>
            <div className="mt-1 px-2 text-[10px] leading-snug">
              Nothing has been computed yet. Advance a stage or run a laboratory and every real operation will appear here with
              the numbers it produced.
            </div>
          </div>
        ) : (
          <AnimatePresence initial={false}>
            {entries.map((entry) => (
              <motion.div
                key={entry.id}
                initial={{ opacity: 0, x: -6 }}
                animate={{ opacity: 1, x: 0 }}
                exit={{ opacity: 0 }}
                transition={{ duration: 0.18 }}
                className="flex gap-2 border-b py-1 last:border-b-0"
                style={{ borderColor: 'rgba(56,189,248,0.05)' }}
              >
                <span className="shrink-0" style={{ color: QSR.inkFaint }}>
                  {timestamp(entry.at)}
                </span>
                <span
                  className="shrink-0 rounded-[2px] px-1 font-bold"
                  style={{ color: LEVEL_COLOR[entry.level], background: tint(LEVEL_COLOR[entry.level], 0.12) }}
                >
                  {LEVEL_TAG[entry.level]}
                </span>
                <span className="min-w-0">
                  <span className="mr-1.5" style={{ color: QSR.inkMuted }}>
                    {entry.source}
                  </span>
                  <span style={{ color: entry.level === 'info' ? QSR.inkSoft : LEVEL_COLOR[entry.level] }}>{entry.text}</span>
                </span>
              </motion.div>
            ))}
          </AnimatePresence>
        )}
      </div>

      <div className="shrink-0 border-t px-3 py-1.5 font-mono text-[9px]" style={{ borderColor: QSR.hairline, color: QSR.inkFaint }}>
        Real events only. Nothing on a timer.
      </div>
    </div>
  );
}
