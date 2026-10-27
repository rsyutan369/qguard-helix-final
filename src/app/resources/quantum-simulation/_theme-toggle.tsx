/**
 * Quantum Simulation Range — theme control and command bar.
 *
 * The choice is the platform's own: it reads and writes `useTheme()` from the
 * app-wide `ThemeProvider`, so it persists under the same key the dashboard
 * uses and a visitor who picked light elsewhere arrives here already in light.
 * There is deliberately no second theme store on this page.
 *
 * Three states, because "follow my OS" is a real preference and not a default
 * to be overwritten the first time someone touches the control:
 *
 *   Light · Dark · Auto
 *
 * The control is a radio group (one choice, always exactly one selected), with
 * the arrow keys moving the selection as a native radio group would.
 */

import React from 'react';
import { motion } from 'framer-motion';
import { Monitor, Moon, Sun, type LucideIcon } from 'lucide-react';
import { useTheme, type ThemeMode } from '@/contexts/theme-context';
import { QSR, tint } from './_theme';

const OPTIONS: Array<{ mode: ThemeMode; label: string; Icon: LucideIcon }> = [
  { mode: 'light', label: 'Light', Icon: Sun },
  { mode: 'dark', label: 'Dark', Icon: Moon },
  { mode: 'system', label: 'Auto', Icon: Monitor },
];

export function ThemeSwitch({ animate = true }: { animate?: boolean }) {
  const { mode, theme, setMode } = useTheme();
  const buttons = React.useRef<Array<HTMLButtonElement | null>>([]);

  const move = (from: number, step: number) => {
    const next = (from + step + OPTIONS.length) % OPTIONS.length;
    setMode(OPTIONS[next].mode);
    buttons.current[next]?.focus();
  };

  const onKeyDown = (event: React.KeyboardEvent, index: number) => {
    if (event.key === 'ArrowRight' || event.key === 'ArrowDown') {
      event.preventDefault();
      move(index, 1);
    } else if (event.key === 'ArrowLeft' || event.key === 'ArrowUp') {
      event.preventDefault();
      move(index, -1);
    }
  };

  return (
    <div
      role="radiogroup"
      aria-label="Colour theme"
      className="qsr-theme-switch relative inline-flex items-center gap-0.5 rounded-full border p-[3px]"
      style={{ borderColor: QSR.hairlineStrong, background: QSR.panelRaised, boxShadow: `0 1px 0 ${tint(QSR.heading, 0.04)}, 0 6px 18px -8px ${tint(QSR.heading, 0.35)}` }}
    >
      {OPTIONS.map(({ mode: optionMode, label, Icon }, index) => {
        const selected = mode === optionMode;
        const title =
          optionMode === 'system' ? `Follow your system setting (currently ${theme})` : `${label} theme`;
        return (
          <button
            key={optionMode}
            ref={(node) => {
              buttons.current[index] = node;
            }}
            type="button"
            role="radio"
            aria-checked={selected}
            aria-label={title}
            title={title}
            tabIndex={selected ? 0 : -1}
            onClick={() => setMode(optionMode)}
            onKeyDown={(event) => onKeyDown(event, index)}
            className="qsr-theme-switch__option relative inline-flex h-7 items-center gap-1.5 rounded-full px-2.5 font-mono text-[10px] font-bold uppercase tracking-[0.14em] outline-none transition-colors sm:px-3"
            style={{ color: selected ? QSR.onAccent : QSR.inkSoft }}
          >
            {selected && (
              <motion.span
                layoutId="qsr-theme-pill"
                aria-hidden
                className="absolute inset-0 rounded-full"
                style={{ background: QSR.live, boxShadow: `0 0 18px ${tint(QSR.live, 0.4)}` }}
                transition={animate ? { type: 'spring', stiffness: 460, damping: 34 } : { duration: 0 }}
              />
            )}
            <Icon className="relative h-3.5 w-3.5" aria-hidden />
            <span className="relative hidden sm:inline">{label}</span>
          </button>
        );
      })}
    </div>
  );
}

/**
 * The page's command bar. Sticky, so the theme control is one gesture away at
 * any depth of a page that is seven sections long.
 */
export function CommandBar({ animate }: { animate: boolean }) {
  return (
    <div
      className="sticky top-0 z-40 border-b backdrop-blur-xl"
      style={{ borderColor: QSR.hairline, background: tint(QSR.ground, 0.78) }}
    >
      <div className="mx-auto flex h-14 max-w-[1500px] items-center justify-between gap-4 px-4 sm:px-6">
        <a href="/" className="flex min-w-0 items-center gap-2.5 outline-none" aria-label="QGuard Helix home">
          <span
            aria-hidden
            className="grid h-7 w-7 shrink-0 place-items-center rounded-md border font-mono text-[11px] font-black"
            style={{ color: QSR.live, borderColor: tint(QSR.live, 0.4), background: tint(QSR.live, 0.1) }}
          >
            Q
          </span>
          <span className="qsr-heading truncate text-[13px] font-extrabold tracking-tight">QGuard Helix</span>
          <span className="hidden font-mono text-[10px] uppercase tracking-[0.2em] md:inline" style={{ color: QSR.inkMuted }}>
            / Quantum Simulation Range
          </span>
        </a>
        <ThemeSwitch animate={animate} />
      </div>
    </div>
  );
}
