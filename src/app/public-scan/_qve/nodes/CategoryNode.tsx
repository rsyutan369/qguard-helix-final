/**
 * Quantum Visualization Engine™ — category node card.
 *
 * One card per scan category, arranged three to a side around the Quantum Core.
 * The card is the engine's *data* surface: everything the visualization animates
 * is also stated here in words, which is what makes the hero usable with motion
 * disabled, on a screen reader, or in a printed assessment.
 *
 * State is read from the event store, never from a local timer:
 *   idle      — dim, dark conduit, no packets
 *   scanning  — rotating icon, cyan ring sweep, live packets
 *   pass      — icon pulses once, emerald badge, beam locks green
 *   warning   — amber badge, verdict names what is missing
 *   critical  — red badge, card shakes once, sparks off the core
 */
'use client';

import React from 'react';
import { motion, useAnimationControls, useReducedMotion } from 'motion/react';
import {
  AlertTriangle,
  Atom,
  BadgeCheck,
  Braces,
  Check,
  FileText,
  Globe,
  KeyRound,
  Loader2,
  Lock,
  MinusCircle,
  Radar,
  ShieldCheck,
  XCircle,
  type LucideIcon,
} from 'lucide-react';
import { cn } from '@/lib/utils';
import { resolveNodeVerdict, type QveNode, type QveNodeKey, type QveResolvedVerdict } from '../types';

/**
 * Icon per node key. Open-ended because the node ring is supplied by whoever
 * mounts the engine — a surface the public scanner does not know about (the
 * Dashboard Scanner's estate categories, say) supplies its own entry here or
 * falls back to the generic radar mark rather than rendering nothing.
 */
const NODE_ICON: Record<string, LucideIcon> = {
  // Public edge (/public-scan)
  dns: Globe,
  tls: Lock,
  certificate: ShieldCheck,
  headers: FileText,
  ocsp: BadgeCheck,
  quantum: Atom,
  // Authenticated estate discovery (/dashboard/scanner)
  discovery: Radar,
  transport: Lock,
  certificates: ShieldCheck,
  identity: KeyRound,
  code: Braces,
  posture: Atom,
};

export interface CategoryNodeProps {
  node: QveNode;
  /** 'left' cards align their beam tap on the right edge, and vice versa. */
  side: 'left' | 'right';
  selected: boolean;
  onSelect: (key: QveNodeKey) => void;
  /** Registers the card element so the beam layer can measure its anchor. */
  registerAnchor: (key: QveNodeKey, element: HTMLElement | null) => void;
  animate: boolean;
}

/**
 * The badge is keyed off the SAME resolved verdict the label and the accent
 * colour use, so a card can never show a green tick beside the word "Critical".
 */
function StatusBadge({ verdict }: { verdict: QveResolvedVerdict }) {
  const shared = 'grid h-5 w-5 shrink-0 place-items-center rounded-full';
  const color = verdict.color;

  switch (verdict.key) {
    case 'scanning':
      return (
        <span className={shared} style={{ backgroundColor: `${color}1f`, color }}>
          <Loader2 className="h-3 w-3 animate-spin" />
        </span>
      );
    case 'secure':
      return (
        <span className={cn(shared, 'ring-1')} style={{ backgroundColor: `${color}1f`, color, boxShadow: `inset 0 0 0 1px ${color}66` }}>
          <Check className="h-3 w-3" strokeWidth={3} />
        </span>
      );
    case 'review':
    case 'at-risk':
      return (
        <span className={shared} style={{ backgroundColor: `${color}1f`, color, boxShadow: `inset 0 0 0 1px ${color}66` }}>
          <AlertTriangle className="h-3 w-3" />
        </span>
      );
    case 'critical':
    case 'failed':
      return (
        <span className={shared} style={{ backgroundColor: `${color}22`, color, boxShadow: `inset 0 0 0 1px ${color}77` }}>
          <XCircle className="h-3 w-3" />
        </span>
      );
    case 'unmeasured':
      return (
        <span className={cn(shared, 'bg-white/[0.04] text-slate-500')} title="Measured nothing — not a pass">
          <MinusCircle className="h-3 w-3" />
        </span>
      );
    default:
      return <span className={cn(shared, 'bg-white/[0.04] text-slate-600')}>—</span>;
  }
}

export const CategoryNode = React.memo(function CategoryNode({
  node,
  side,
  selected,
  onSelect,
  registerAnchor,
  animate,
}: CategoryNodeProps) {
  const reduce = useReducedMotion();
  const Icon = NODE_ICON[node.key] ?? Radar;
  /* ONE resolved state drives the label, the accent, the badge, the border, the
     progress sweep and the beam tap. There is deliberately no second source. */
  const verdict = resolveNodeVerdict(node);
  const color = verdict.color;
  const live = node.state !== 'idle';
  const alert = verdict.alert;
  /* The surface-specific phrase the derivation produced ("Legacy exposed",
     "Untrusted chain", "Hybrid PQ") is real information and is kept — but as
     muted context under the state, never as the coloured headline, because an
     arbitrary phrase cannot be guaranteed to agree with the accent it is
     painted in. That guarantee is the whole point of `resolveNodeVerdict`. */
  const context =
    node.hasEvidence && node.verdict && node.verdict !== verdict.label ? node.verdict : null;
  const reference = React.useRef<HTMLButtonElement>(null);

  React.useEffect(() => {
    registerAnchor(node.key, reference.current);
    return () => registerAnchor(node.key, null);
  }, [node.key, registerAnchor]);

  const motionEnabled = animate && !reduce;

  // A real critical finding shakes the card once: a bounded 350ms nudge fired
  // imperatively per event. Driving it from `animate` instead would restart the
  // keyframes on every unrelated re-render, turning a single alert into a
  // permanent tremor.
  const shake = useAnimationControls();
  React.useEffect(() => {
    if (!motionEnabled || !alert || !node.updatedAt) return;
    void shake.start({ x: [0, -3, 3, -2, 2, 0] }, { duration: 0.35 });
  }, [motionEnabled, alert, node.updatedAt, shake]);

  return (
    <motion.button
      ref={reference}
      type="button"
      onClick={() => onSelect(node.key)}
      aria-pressed={selected}
      // The card is the accessible name for everything the beam animates.
      aria-label={`${node.title}: ${verdict.label}.${context ? ` ${context}.` : ''} ${node.lines.join('. ')}`}
      title={verdict.basis}
      animate={shake}
      className={cn(
        'group relative w-full overflow-hidden rounded-xl border px-3 py-2.5 text-left transition-colors duration-300',
        'bg-[#070d1b]/85 backdrop-blur-md',
        selected ? 'border-cyan-400/45' : live ? 'border-white/[0.1]' : 'border-white/[0.06]',
        'hover:border-cyan-400/35 focus-visible:outline-none focus-visible:ring-2 focus-visible:ring-cyan-400/50',
      )}
      style={
        live
          ? { boxShadow: `inset 0 0 0 1px ${color}1f, 0 0 26px -18px ${color}` }
          : undefined
      }
    >
      {/* Node progress sweep along the top edge — real per-node completion. */}
      <span
        aria-hidden
        className="absolute inset-x-0 top-0 h-[2px] origin-left transition-transform duration-700"
        style={{
          background: `linear-gradient(90deg, ${color}, transparent)`,
          transform: `scaleX(${Math.max(0, Math.min(100, node.progress)) / 100})`,
        }}
      />

      <div className="flex items-start gap-2.5">
        <motion.span
          aria-hidden
          className="grid h-8 w-8 shrink-0 place-items-center rounded-lg border"
          style={{ borderColor: `${color}44`, backgroundColor: `${color}12`, color }}
          animate={
            motionEnabled && verdict.key === 'scanning'
              ? { rotate: 360 }
              : motionEnabled && verdict.key === 'secure'
                ? { scale: [1, 1.12, 1] }
                : { rotate: 0, scale: 1 }
          }
          transition={
            verdict.key === 'scanning'
              ? { duration: 3.2, repeat: Infinity, ease: 'linear' }
              : { duration: 1.8, repeat: Infinity, repeatDelay: 2.4 }
          }
        >
          <Icon className="h-4 w-4" />
        </motion.span>

        <div className="min-w-0 flex-1">
          <div className="flex items-center justify-between gap-2">
            <p className="truncate font-mono text-[10px] font-bold uppercase tracking-[0.13em] text-slate-200">
              {node.title}
            </p>
            <StatusBadge verdict={verdict} />
          </div>
          <p className="mt-0.5 flex items-baseline gap-1.5 text-[11.5px] font-bold">
            <span className="truncate" style={{ color: live ? color : '#64748b' }}>
              {verdict.label}
            </span>
            {node.score !== null && node.hasEvidence && (
              <span className="shrink-0 font-mono text-[9.5px] font-bold tabular-nums" style={{ color: live ? color : '#64748b' }}>
                {node.score}
              </span>
            )}
          </p>
          {context && (
            <p className="truncate text-[10px] leading-snug text-slate-400" title={context}>
              {context}
            </p>
          )}
          <div className="mt-0.5 space-y-[1px]">
            {node.lines.slice(0, 2).map((line) => (
              <p key={line} className="truncate text-[10.5px] leading-snug text-slate-500" title={line}>
                {line}
              </p>
            ))}
          </div>
        </div>
      </div>

      {/* Beam tap marker on the edge facing the core. */}
      <span
        aria-hidden
        className={cn('absolute top-1/2 h-1.5 w-1.5 -translate-y-1/2 rounded-full', side === 'left' ? '-right-[3px]' : '-left-[3px]')}
        style={{ backgroundColor: color, opacity: live ? 1 : 0.65, boxShadow: `0 0 8px ${color}` }}
      />
    </motion.button>
  );
});
