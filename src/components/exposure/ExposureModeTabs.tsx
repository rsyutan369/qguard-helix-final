'use client';

/**
 * Exposure mode tabs — Web / Local / Dev (§3).
 *
 * "The active tab must have a neon cyan/teal highlight, an animated bottom
 *  indicator, a subtle glow, the correct icon, accessible keyboard navigation,
 *  an ARIA selected state and a smooth Framer Motion transition."
 *
 * Every one of those is here. Two details worth naming:
 *
 *  • The moving indicator is ONE `motion.span` with a `layoutId`, not three
 *    conditionally-rendered bars. That is what makes it slide between tabs
 *    instead of cross-fading, and it costs nothing when motion is reduced
 *    because Framer honours `prefers-reduced-motion` on layout animations.
 *
 *  • Keyboard navigation follows the WAI-ARIA tabs pattern properly: arrows
 *    move and activate, Home/End jump to the ends, and only the active tab is
 *    in the tab order (`tabIndex={-1}` on the others), so Tab leaves the
 *    tablist rather than walking through it.
 */

import React from 'react';
import { motion } from 'motion/react';
import { Code2, Globe, Lock, MonitorSmartphone } from 'lucide-react';
import { cn } from '@/lib/utils';
import type { ScanMode } from '@/lib/scanner/exposure/types';

const TABS: Array<{ id: ScanMode; label: string; icon: typeof Globe; hint: string }> = [
  { id: 'web', label: 'Web', icon: Globe, hint: 'Internet-facing exposure assessment' },
  { id: 'local', label: 'Local', icon: MonitorSmartphone, hint: 'Local device, filesystem and codebase assessment' },
  { id: 'dev', label: 'Dev', icon: Code2, hint: 'Repository, container, Kubernetes and cloud-native assessment' },
];

export interface ExposureModeTabsProps {
  value: ScanMode;
  onChange: (mode: ScanMode) => void;
  /** Per-tab badge, e.g. a live finding count. */
  badges?: Partial<Record<ScanMode, string | number>>;
  /** Disable a mode with a reason, shown as the title. */
  disabled?: Partial<Record<ScanMode, string>>;
  /**
   * Mark a mode as requiring a plan, with the reason as its tooltip.
   *
   * Deliberately NOT `disabled`: a locked tab stays clickable, because the
   * panel behind it is what explains the feature and makes the case for the
   * plan. Hiding it behind a dead tab would mean a visitor never learns what
   * they are being asked to pay for.
   */
  locked?: Partial<Record<ScanMode, string>>;
  className?: string;
  /** `layoutId` scope, so two tab strips on one page do not share an indicator. */
  scope?: string;
}

export function ExposureModeTabs({ value, onChange, badges, disabled, locked, className, scope = 'exposure' }: ExposureModeTabsProps) {
  const refs = React.useRef<Array<HTMLButtonElement | null>>([]);

  const move = (from: number, delta: number) => {
    const count = TABS.length;
    for (let step = 1; step <= count; step += 1) {
      const index = (from + delta * step + count * count) % count;
      if (disabled?.[TABS[index].id]) continue;
      refs.current[index]?.focus();
      onChange(TABS[index].id);
      return;
    }
  };

  const onKeyDown = (event: React.KeyboardEvent, index: number) => {
    switch (event.key) {
      case 'ArrowRight':
      case 'ArrowDown':
        event.preventDefault();
        move(index, 1);
        break;
      case 'ArrowLeft':
      case 'ArrowUp':
        event.preventDefault();
        move(index, -1);
        break;
      case 'Home':
        event.preventDefault();
        move(-1, 1);
        break;
      case 'End':
        event.preventDefault();
        move(TABS.length, -1);
        break;
      default:
        break;
    }
  };

  return (
    <div
      role="tablist"
      aria-label="Assessment mode"
      className={cn(
        'inline-flex items-center gap-1 rounded-xl border border-white/[0.07] bg-[#060b16]/80 p-1 backdrop-blur-xl',
        className,
      )}
    >
      {TABS.map((tab, index) => {
        const active = value === tab.id;
        const lockedReason = disabled?.[tab.id];
        const planReason = locked?.[tab.id];
        const badge = badges?.[tab.id];

        return (
          <button
            key={tab.id}
            ref={(element) => {
              refs.current[index] = element;
            }}
            type="button"
            role="tab"
            id={`exposure-tab-${tab.id}`}
            aria-selected={active}
            aria-controls={`exposure-panel-${tab.id}`}
            aria-disabled={Boolean(lockedReason)}
            tabIndex={active ? 0 : -1}
            title={lockedReason ?? planReason ?? tab.hint}
            disabled={Boolean(lockedReason)}
            onClick={() => !lockedReason && onChange(tab.id)}
            onKeyDown={(event) => onKeyDown(event, index)}
            className={cn(
              'relative inline-flex items-center gap-2 rounded-lg px-3.5 py-2 text-[13px] font-bold transition-colors duration-200',
              'focus-visible:outline-none focus-visible:ring-2 focus-visible:ring-cyan-400/60',
              active ? 'text-cyan-300' : 'text-slate-400 hover:text-slate-200',
              lockedReason && 'cursor-not-allowed opacity-40 hover:text-slate-400',
            )}
          >
            {active && (
              <motion.span
                layoutId={`${scope}-mode-tab-active`}
                aria-hidden
                className="absolute inset-0 rounded-lg border border-cyan-400/30 bg-cyan-400/[0.10] shadow-[0_0_26px_-8px_rgba(34,211,238,0.75)]"
                transition={{ type: 'spring', stiffness: 420, damping: 34 }}
              />
            )}
            <tab.icon aria-hidden className="relative h-4 w-4 shrink-0" />
            <span className="relative whitespace-nowrap">{tab.label}</span>
            {planReason && !lockedReason && (
              <>
                <Lock
                  aria-hidden
                  className={cn('relative h-3 w-3 shrink-0', active ? 'text-cyan-300/80' : 'text-amber-400/70')}
                />
                {/* The padlock is decorative; this is what a screen reader
                    reads, because `title` is not reliably announced once the
                    button already has a name. */}
                <span className="sr-only">, requires a plan: {planReason}</span>
              </>
            )}
            {badge !== undefined && badge !== null && badge !== '' && (
              <span
                className={cn(
                  'relative rounded px-1.5 py-0.5 font-mono text-[10px] font-black',
                  active ? 'bg-cyan-400/20 text-cyan-200' : 'bg-white/[0.07] text-slate-400',
                )}
              >
                {badge}
              </span>
            )}
            {active && (
              <motion.span
                layoutId={`${scope}-mode-tab-underline`}
                aria-hidden
                className="absolute -bottom-1 left-3 right-3 h-[2px] rounded-full bg-gradient-to-r from-cyan-400 via-cyan-300 to-violet-400"
                transition={{ type: 'spring', stiffness: 420, damping: 34 }}
              />
            )}
          </button>
        );
      })}
    </div>
  );
}

/** One-line description of the selected mode, shown beneath the tab strip. */
export function ExposureModeCaption({ mode }: { mode: ScanMode }) {
  const tab = TABS.find((entry) => entry.id === mode);
  if (!tab) return null;
  return (
    <p className="mt-2 font-mono text-[10px] uppercase tracking-[0.16em] text-slate-500">{tab.hint}</p>
  );
}
