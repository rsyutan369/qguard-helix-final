/**
 * Dashboard Scanner — node evidence inspector.
 *
 * The authenticated counterpart to the public hero's `NodeInspector`. Same
 * chrome — a transient HUD docked inside the visualization band, Escape to
 * close — but the body is the tenant's own scan evidence: the TLS analysis, the
 * parsed certificate chain, the repository and Web Crypto passes, the header
 * probe and the Scanner_2 enterprise pass, plus the real execution state of the
 * scanner modules behind that surface.
 *
 * The public inspector cannot be reused directly: its evidence tables read a
 * `PublicScanReport`, a shape the authenticated scanner does not produce. What
 * IS shared is the design language, which is why this file mirrors its markup
 * rather than inventing a second visual idiom.
 */
'use client';

import React from 'react';
import { AnimatePresence, motion, useReducedMotion } from 'motion/react';
import { X } from 'lucide-react';
import { cn } from '@/lib/utils';
import { beamColor, type QveNode } from '@/app/public-scan/_qve';
import { Meter } from '@/components/quantum-scan/ui';
import type { NodeEvidence } from './_intel';

const MODULE_STATUS_TONE: Record<string, string> = {
  Completed: '#34d399',
  'No findings': '#34d399',
  Running: '#38bdf8',
  Queued: '#64748b',
  Skipped: '#64748b',
  Failed: '#f43f5e',
};

const THREAT_TONE: Record<string, string> = {
  CRITICAL: '#f43f5e',
  HIGH: '#fb923c',
  MEDIUM: '#fbbf24',
  LOW: '#34d399',
  SAFE: '#22d3ee',
};

export interface ScannerNodeInspectorProps {
  node: QveNode | null;
  evidence: NodeEvidence | null;
  onClose: () => void;
  animate: boolean;
}

export function ScannerNodeInspector({ node, evidence, onClose, animate }: ScannerNodeInspectorProps) {
  const reduce = useReducedMotion();
  const motionEnabled = animate && !reduce;

  // Escape closes — the panel is a transient HUD, not a route.
  React.useEffect(() => {
    if (!node) return;
    const onKeyDown = (event: KeyboardEvent) => {
      if (event.key === 'Escape') onClose();
    };
    window.addEventListener('keydown', onKeyDown);
    return () => window.removeEventListener('keydown', onKeyDown);
  }, [node, onClose]);

  return (
    <AnimatePresence>
      {node && (
        <motion.div
          initial={motionEnabled ? { opacity: 0, y: 10, scale: 0.98 } : false}
          animate={{ opacity: 1, y: 0, scale: 1 }}
          exit={motionEnabled ? { opacity: 0, y: 6, scale: 0.99 } : { opacity: 0 }}
          transition={{ duration: 0.24, ease: [0.22, 1, 0.36, 1] }}
          role="dialog"
          aria-label={`${node.title} evidence`}
          className={cn(
            'absolute inset-x-3 bottom-3 z-30 max-h-[78%] overflow-y-auto rounded-xl border border-cyan-400/25',
            'bg-[#050a15]/96 p-3.5 shadow-[0_30px_80px_-30px_rgba(0,0,0,0.95)] backdrop-blur-2xl',
            'sm:inset-x-auto sm:left-1/2 sm:w-[30rem] sm:-translate-x-1/2',
          )}
        >
          <div className="flex items-start justify-between gap-3">
            <div className="min-w-0">
              <p className="font-mono text-[9.5px] font-bold uppercase tracking-[0.2em] text-cyan-400/80">
                {node.title}
              </p>
              <p className="mt-0.5 text-[13px] font-black" style={{ color: beamColor(node) }}>
                {node.verdict}
              </p>
            </div>
            <div className="flex shrink-0 items-center gap-2">
              {evidence?.score !== null && evidence !== null && (
                <span className="text-right">
                  <span className="block font-mono text-[9px] uppercase tracking-widest text-slate-600">Posture</span>
                  <span className="block text-[13px] font-black tabular-nums" style={{ color: beamColor(node) }}>
                    {evidence.score}
                  </span>
                </span>
              )}
              <button
                type="button"
                onClick={onClose}
                aria-label="Close evidence panel"
                className="grid h-7 w-7 shrink-0 place-items-center rounded-lg text-slate-400 transition-colors hover:bg-white/[0.07] hover:text-white"
              >
                <X className="h-3.5 w-3.5" />
              </button>
            </div>
          </div>

          {evidence && evidence.score !== null && (
            <Meter value={evidence.score} color={beamColor(node)} className="mt-2.5 h-1" />
          )}

          <div className="mt-3 space-y-3">
            {!evidence || evidence.rows.length === 0 ? (
              <p className="text-[11px] leading-relaxed text-slate-400">
                {evidence?.emptyReason ??
                  'No evidence yet. Run an authorized scan and this panel will show exactly what the scanner observed for this surface — nothing is pre-filled.'}
              </p>
            ) : (
              <dl className="space-y-1">
                {evidence.rows.map((row) => (
                  <div
                    key={row.label}
                    className="flex items-baseline justify-between gap-3 border-b border-white/[0.05] pb-1 last:border-0"
                    title={row.detail}
                  >
                    <dt className="shrink-0 font-mono text-[9.5px] uppercase tracking-[0.12em] text-slate-500">
                      {row.label}
                    </dt>
                    <dd
                      className="truncate text-right text-[10.5px] font-semibold"
                      style={{ color: row.tone ?? '#cbd5e1' }}
                      title={row.value}
                    >
                      {row.value}
                    </dd>
                  </div>
                ))}
              </dl>
            )}

            {/* Findings routed to this surface — the operator's next action. */}
            {evidence && evidence.findings.length > 0 && (
              <div className="border-t border-white/[0.06] pt-2.5">
                <p className="font-mono text-[9px] font-bold uppercase tracking-[0.16em] text-slate-500">
                  Findings on this surface
                </p>
                <ul className="mt-1.5 space-y-1">
                  {evidence.findings.map((finding) => (
                    <li key={finding.id} className="flex items-baseline gap-2 text-[10.5px]">
                      <span
                        className="mt-[5px] h-1.5 w-1.5 shrink-0 rounded-full"
                        style={{ backgroundColor: THREAT_TONE[finding.threatLevel] ?? '#64748b' }}
                      />
                      <span className="min-w-0 flex-1 truncate font-mono text-slate-300" title={finding.location}>
                        {finding.algorithm}
                      </span>
                      <span
                        className="shrink-0 font-mono text-[9px] font-bold uppercase tracking-wider"
                        style={{ color: THREAT_TONE[finding.threatLevel] ?? '#64748b' }}
                      >
                        {finding.threatLevel}
                      </span>
                    </li>
                  ))}
                </ul>
              </div>
            )}

            {/* Which modules produced this surface, and how they actually ended. */}
            {evidence && evidence.modules.length > 0 && (
              <div className="border-t border-white/[0.06] pt-2.5">
                <p className="font-mono text-[9px] font-bold uppercase tracking-[0.16em] text-slate-500">
                  Modules behind this surface
                </p>
                <ul className="mt-1.5 space-y-1">
                  {evidence.modules.map((module) => (
                    <li key={module.id} className="flex items-baseline gap-2 text-[10.5px]">
                      <span className="min-w-0 flex-1 truncate text-slate-400" title={module.name}>
                        {module.name}
                      </span>
                      {module.durationMs !== null && (
                        <span className="shrink-0 font-mono text-[9px] tabular-nums text-slate-600">
                          {module.durationMs} ms
                        </span>
                      )}
                      <span
                        className="shrink-0 font-mono text-[9px] font-bold uppercase tracking-wider"
                        style={{ color: MODULE_STATUS_TONE[module.status] ?? '#64748b' }}
                      >
                        {module.status}
                      </span>
                    </li>
                  ))}
                </ul>
              </div>
            )}
          </div>
        </motion.div>
      )}
    </AnimatePresence>
  );
}
