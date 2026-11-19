/**
 * Quantum Simulation Range — theme control and command bar.
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
import type { ThemeMode } from '@/contexts/theme-context';
import { QSR, tint, type QsrTheme } from './_theme';

const OPTIONS: Array<{ mode: ThemeMode; label: string; Icon: LucideIcon }> = [
  { mode: 'light', label: 'Light', Icon: Sun },
  { mode: 'dark', label: 'Dark', Icon: Moon },
  { mode: 'system', label: 'Auto', Icon: Monitor },
];

type ThemeControl = { animate: boolean; mode: ThemeMode; theme: QsrTheme; setMode: (mode: ThemeMode) => void };

function ThemeSwitch({ animate, mode, theme, setMode }: ThemeControl) {
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
export function CommandBar(props: ThemeControl) {
  return (
    <div className="qsr-command">
      <div className="lp-wrap qsr-command__inner">
        <a href="/" className="qsr-command__brand" aria-label="Qguard Helix home">
          <img src="/NEW_LOGO.png" alt="" width="38" height="38" />
          <span>Qguard Helix</span>
        </a>
        <ThemeSwitch {...props} />
      </div>
    </div>
  );
}
