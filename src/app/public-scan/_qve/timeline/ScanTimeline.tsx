/**
 * Quantum Visualization Engine™ — Event Timeline.
 *
 * Two presentations of the same real event stream:
 *
 *   • {@link ScanTicker}   — a single-line readout of the newest event, which
 *     replaces the hero's static strapline while a scan is live. Keeps the hero
 *     layout identical at rest and turns it into a console the moment work starts.
 *   • {@link ScanTimeline} — the full mm:ss log, newest entries animating in, for
 *     the console drawer under the hero.
 *
 * Clocks are elapsed time from the real SCAN_STARTED event, not from a mounted
 * interval, so a cached result that returns in 200ms reads 00:00 across the board
 * instead of pretending to take eleven seconds.
 */
'use client';

import React from 'react';
import { AnimatePresence, motion } from 'motion/react';
import { AlertTriangle, Check, Loader2, XCircle } from 'lucide-react';
import { cn } from '@/lib/utils';
import { QVE_COLOR, type QveTimelineEntry, type ScanEventStatus } from '../types';

function statusColor(status: ScanEventStatus): string {
  switch (status) {
    case 'pass':
      return QVE_COLOR.pass;
    case 'warning':
      return QVE_COLOR.warning;
    case 'critical':
    case 'failed':
      return QVE_COLOR.critical;
    case 'running':
      return QVE_COLOR.scanning;
    default:
      return '#94a3b8';
  }
}

function StatusGlyph({ status, className }: { status: ScanEventStatus; className?: string }) {
  const shared = cn('h-3 w-3 shrink-0', className);
  switch (status) {
    case 'pass':
      return <Check className={shared} strokeWidth={3} />;
    case 'warning':
      return <AlertTriangle className={shared} />;
    case 'critical':
    case 'failed':
      return <XCircle className={shared} />;
    case 'running':
      return <Loader2 className={cn(shared, 'animate-spin')} />;
    default:
      return <span className={cn(shared, 'grid place-items-center text-[9px]')}>·</span>;
  }
}

/* -------------------------------------------------------------------- ticker - */

export const ScanTicker = React.memo(function ScanTicker({
  entry,
  animate,
}: {
  entry: QveTimelineEntry | null;
  animate: boolean;
}) {
  if (!entry) return null;
  const color = statusColor(entry.status);

  return (
    <div className="flex min-w-0 items-center gap-2.5 font-mono text-[10px] uppercase tracking-[0.12em]">
      <span className="shrink-0 font-bold text-slate-500">{entry.clock}</span>
      <span className="h-3 w-px shrink-0 bg-white/10" />
      <AnimatePresence mode="wait" initial={false}>
        <motion.span
          key={entry.id}
          initial={animate ? { opacity: 0, y: 6 } : false}
          animate={{ opacity: 1, y: 0 }}
          exit={animate ? { opacity: 0, y: -6 } : { opacity: 0 }}
          transition={{ duration: 0.22 }}
          className="flex min-w-0 items-center gap-1.5"
          style={{ color }}
        >
          <StatusGlyph status={entry.status} />
          <span className="truncate font-bold">{entry.label}</span>
          {entry.detail && (
            <span className="hidden truncate font-normal normal-case tracking-normal text-slate-500 sm:inline">
              — {entry.detail}
            </span>
          )}
        </motion.span>
      </AnimatePresence>
    </div>
  );
});

/* ------------------------------------------------------------------ timeline - */

export const ScanTimeline = React.memo(function ScanTimeline({
  entries,
  animate,
  emptyHint,
}: {
  entries: QveTimelineEntry[];
  animate: boolean;
  emptyHint: string;
}) {
  const scroller = React.useRef<HTMLDivElement>(null);
  const latestId = entries.length ? entries[entries.length - 1].id : null;

  // Follow the newest entry, but only within this container — the page must
  // never scroll itself because a log line arrived.
  React.useEffect(() => {
    const element = scroller.current;
    if (!element || !latestId) return;
    element.scrollTo({ top: element.scrollHeight, behavior: animate ? 'smooth' : 'auto' });
  }, [latestId, animate]);

  if (!entries.length) {
    return <p className="px-1 py-3 text-[11.5px] text-slate-500">{emptyHint}</p>;
  }

  return (
    <div ref={scroller} className="max-h-52 overflow-y-auto pr-1">
      <ol className="space-y-0.5">
        {entries.map((entry) => {
          const color = statusColor(entry.status);
          return (
            <motion.li
              key={entry.id}
              initial={animate ? { opacity: 0, x: -6 } : false}
              animate={{ opacity: 1, x: 0 }}
              transition={{ duration: 0.28, ease: [0.22, 1, 0.36, 1] }}
              className="flex items-start gap-2.5 rounded-md px-1.5 py-1 hover:bg-white/[0.025]"
            >
              <span className="mt-[3px] shrink-0 font-mono text-[10px] font-bold tabular-nums text-slate-500">
                {entry.clock}
              </span>
              <span className="mt-[2px]" style={{ color }}>
                <StatusGlyph status={entry.status} />
              </span>
              <div className="min-w-0 flex-1">
                <p className="truncate text-[11.5px] font-semibold text-slate-200" title={entry.label}>
                  {entry.label}
                </p>
                {entry.detail && (
                  <p className="truncate text-[10px] text-slate-500" title={entry.detail}>
                    {entry.detail}
                  </p>
                )}
              </div>
            </motion.li>
          );
        })}
      </ol>
    </div>
  );
});
